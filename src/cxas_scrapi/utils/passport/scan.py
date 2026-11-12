# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ruff: noqa: E501

"""Text scan of the agent files for the Google Cloud resources they name.

Finds Cloud Run URLs, Cloud Storage URIs, Secret Manager paths, BigQuery
tables in SQL (Python string literals included), the logging settings of
app.json, and the names of other Google Cloud resources.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cxas_scrapi.utils.passport.files import (
    is_runtime_file,
    line_of,
    read_json,
    read_text,
)
from cxas_scrapi.utils.passport.model import ExternalRef
from cxas_scrapi.utils.passport.sql_refs import (
    DATASET_CONST_NAMES,
    python_strings,
    sql_table_refs,
)

if TYPE_CHECKING:
    from pathlib import Path

RUN_URL_RE = re.compile(
    r"https?://(?P<host>[a-z0-9][a-z0-9.-]*\.run\.app)(?P<path>/[^\s\"'`<>\\)\]},]*)?"
)
RUN_DETERMINISTIC_HOST_RE = re.compile(
    r"^(?P<service>[a-z0-9-]+?)-(?P<number>\d{6,15})\.(?P<region>[a-z]+-[a-z]+\d+)\.run\.app$"
)
RUN_HASH_HOST_RE = re.compile(
    r"^(?P<service>[a-z0-9-]+?)-(?P<hash>[a-z0-9]{6,14})-(?P<code>[a-z]{2,4})\.a\.run\.app$"
)
GCS_URI_RE = re.compile(
    r"gs://(?P<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?P<path>/[^\s\"'`<>\\)\]},]*)?"
)
GCS_HTTP_RE = re.compile(
    r"https://storage\.(?:googleapis|cloud\.google)\.com/(?P<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])(?P<path>/[^\s\"'`<>\\)\]},?]*)?"
)
SECRET_RE = re.compile(
    r"projects/(?P<project>[A-Za-z0-9._:-]+)/secrets/(?P<secret>[A-Za-z0-9_-]+)(?:/versions/(?P<version>[A-Za-z0-9_-]+))?"
)

# Other Google Cloud resources an agent can name.
_SEG = r"[^/\"'\s`,;)}\]>]+"
OTHER_RESOURCE_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Vertex AI Search",
        re.compile(
            rf"projects/{_SEG}/locations/{_SEG}/(?:collections/{_SEG}/)?(?:dataStores|engines)/{_SEG}"
        ),
    ),
    (
        "Vertex AI",
        re.compile(
            rf"projects/{_SEG}/locations/{_SEG}/(?:endpoints|ragCorpora|indexEndpoints|featureOnlineStores|cachedContents)/{_SEG}"
        ),
    ),
    (
        "Cloud Functions",
        re.compile(
            r"https?://[a-z0-9-]+-[a-zA-Z0-9_-]+\.cloudfunctions\.net/[A-Za-z0-9_-]+"
        ),
    ),
    (
        "API Gateway",
        re.compile(r"https?://[a-zA-Z0-9-]+\.[a-z0-9-]+\.gateway\.dev"),
    ),
    (
        "App Engine",
        re.compile(
            r"https?://(?:[a-zA-Z0-9-]+-dot-)?[a-zA-Z0-9_-]+\.(?:[a-z0-9-]+\.r\.)?appspot\.com"
        ),
    ),
    (
        "Cloud Spanner",
        re.compile(rf"projects/{_SEG}/instances/{_SEG}/databases/{_SEG}"),
    ),
    (
        "AlloyDB",
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/clusters/{_SEG}"),
    ),
    (
        "Pub/Sub",
        re.compile(rf"projects/{_SEG}/(?:topics|subscriptions)/{_SEG}"),
    ),
    (
        "Cloud Tasks",
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/queues/{_SEG}"),
    ),
    (
        "Workflows",
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/workflows/{_SEG}"),
    ),
    (
        "Model Armor",
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/templates/{_SEG}"),
    ),
    (
        "Cloud DLP",
        re.compile(
            rf"projects/{_SEG}/(?:locations/{_SEG}/)?(?:inspectTemplates|deidentifyTemplates)/{_SEG}"
        ),
    ),
)


@dataclass
class Refs:
    """What the agent files name, with the file and line of each mention."""

    run_urls: list[tuple[str, str, str, int]] = field(
        default_factory=list
    )  # url, host, file, line
    gcs: list[tuple[str, str | None, str, int]] = field(
        default_factory=list
    )  # bucket, object, file, line
    bq: list[tuple[str | None, str, str | None, str, int]] = field(
        default_factory=list
    )  # project, dataset, table, file, line
    secrets: list[tuple[str, str, str, int]] = field(
        default_factory=list
    )  # project, secret, file, line
    bq_export: tuple[str | None, str | None, str] | None = (
        None  # project, dataset, file
    )
    log_buckets: list[tuple[str, str, str]] = field(
        default_factory=list
    )  # bucket, purpose, file
    other: list[ExternalRef] = field(default_factory=list)
    numbers: Counter = field(default_factory=Counter)


def strip_trailing(text: str) -> str:
    return text.rstrip(".,;:")


def scan_python_bigquery(rel: str, text: str, refs: Refs) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in tree.body:
        if not (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        names = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if not names & DATASET_CONST_NAMES:
            continue
        value = node.value.value.strip("`").strip()
        if not value or "$" in value or "{" in value:
            continue
        if "." in value:
            project, dataset = value.split(".", 1)
            refs.bq.append((project, dataset, None, rel, node.lineno))
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            refs.bq.append((None, value, None, rel, node.lineno))
    for string, line in python_strings(text):
        for project, dataset, table in sql_table_refs(string):
            refs.bq.append((project, dataset, table, rel, line))


def scan_logging_settings(root: Path, refs: Refs) -> None:
    sources = [
        ("app.json", read_json(root / "app.json").get("loggingSettings"))
    ]
    env_app = read_json(root / "environment.json").get("app")
    if isinstance(env_app, dict):
        sources.append(("environment.json", env_app.get("loggingSettings")))
    for rel, settings in sources:
        if not isinstance(settings, dict):
            continue
        bq_export = settings.get("bigqueryExportSettings")
        if (
            isinstance(bq_export, dict)
            and bq_export.get("dataset")
            and str(bq_export.get("dataset")) != "$env_var"
        ):
            project = (
                str(bq_export.get("project") or "")
                .replace("projects/", "")
                .strip()
                or None
            )
            if project == "$env_var":
                project = None
            refs.bq_export = (project, str(bq_export["dataset"]), rel)
        for key, purpose in (
            ("audioRecordingConfig", "audio_recordings"),
            ("evaluationAudioRecordingConfig", "evaluation_audio"),
        ):
            cfg = settings.get(key)
            if isinstance(cfg, dict) and isinstance(cfg.get("gcsBucket"), str):
                raw = cfg["gcsBucket"].strip()
                if raw and raw != "$env_var":
                    bucket = raw.removeprefix("gs://").split("/", 1)[0]
                    if bucket:
                        refs.log_buckets.append((bucket, purpose, rel))


def scan_agent_files(root: Path, files: list[Path]) -> Refs:
    refs = Refs()
    for path in files:
        rel = str(path.relative_to(root))
        if not is_runtime_file(rel):
            continue
        text = read_text(path)
        if text is None:
            continue
        for m in RUN_URL_RE.finditer(text):
            url = strip_trailing(m.group(0))
            host = m.group("host")
            refs.run_urls.append((url, host, rel, line_of(text, m.start())))
            det = RUN_DETERMINISTIC_HOST_RE.match(host)
            if det:
                refs.numbers[det.group("number")] += 1
        for regex in (GCS_URI_RE, GCS_HTTP_RE):
            for m in regex.finditer(text):
                obj = strip_trailing((m.group("path") or "")[1:]) or None
                refs.gcs.append(
                    (m.group("bucket"), obj, rel, line_of(text, m.start()))
                )
        for m in SECRET_RE.finditer(text):
            project = m.group("project")
            if project.startswith("$"):
                continue
            refs.secrets.append(
                (project, m.group("secret"), rel, line_of(text, m.start()))
            )
            if project.isdigit():
                refs.numbers[project] += 1
        if path.suffix == ".py":
            scan_python_bigquery(rel, text, refs)
        for service, regex in OTHER_RESOURCE_RES:
            for m in regex.finditer(text):
                refs.other.append(
                    ExternalRef(
                        service,
                        strip_trailing(m.group(0)),
                        rel,
                        line_of(text, m.start()),
                    )
                )
    scan_logging_settings(root, refs)
    return refs


def guess_project_id(refs: Refs, app_name: str | None) -> str | None:
    if app_name and app_name.startswith("projects/"):
        return app_name.split("/")[1]
    counter: Counter = Counter()
    for project, *_ in refs.secrets:
        if not project.isdigit():
            counter[project] += 1
    for project, *_ in refs.bq:
        if project:
            counter[project] += 1
    if refs.bq_export and refs.bq_export[0]:
        counter[refs.bq_export[0]] += 1
    return counter.most_common(1)[0][0] if counter else None
