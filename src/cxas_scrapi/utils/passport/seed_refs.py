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

"""Seeds from app settings (app.json + environment.json) and the text scan.

Called through `seeds.Seeder.app_settings` and `seeds.Seeder.text_refs`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.files import usage_label
from cxas_scrapi.utils.passport.graph import Evidence, NodeRef
from cxas_scrapi.utils.passport.urls import classify_url

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.scan import Refs
    from cxas_scrapi.utils.passport.seeds import Seeder

_URL_SERVICES = {"Cloud Functions", "API Gateway", "App Engine"}
_SETTINGS_FILES = ("app.json", "environment.json")


def overlay(base: Any, env: Any) -> Any:
    """`base` with the values of `env` on top (CES exports `$env_var` in the agent
    files and the real value in environment.json)."""
    if isinstance(base, dict) and isinstance(env, dict):
        out = dict(base)
        for key, value in env.items():
            out[key] = overlay(base.get(key), value)
        return out
    return base if env in (None, "") else env


def seed_app_settings(
    seeder: Seeder,
    app_data: dict[str, Any],
    env_data: dict[str, Any],
    app_id: str | None = None,
) -> None:
    env_app = (
        env_data.get("app") if isinstance(env_data.get("app"), dict) else {}
    )
    data = overlay(app_data, env_app)
    rel = "app.json"
    seeder._also = ("environment.json",)
    settings = data.get("loggingSettings") or {}
    bq = settings.get("bigqueryExportSettings") or {}
    dataset = str(bq.get("dataset") or "")
    if dataset and dataset != "$env_var":
        if bq.get("enabled") is False:
            seeder.notes.append(
                f"BigQuery export dataset `{dataset}` is configured but the export is disabled: not followed"
            )
        else:
            project = (
                str(bq.get("project") or "").removeprefix("projects/").strip()
            )
            project = seeder.ctx.project_key(
                None if project in ("", "$env_var") else project
            )
            # CES writes one table per app, named after the app ID; other apps
            # may log to the same dataset.
            app = str(app_data.get("name") or "").rsplit("/", 1)[-1] or (
                app_id or ""
            )
            seeder.graph.add(
                ids.BQ,
                ids.dataset(seeder.ctx, project, dataset),
                seeder._ev(
                    rel,
                    f'"{dataset}"',
                    "CES conversation logging (loggingSettings.bigqueryExportSettings): "
                    + (
                        "CES writes this app's conversation table here (named after the app ID)"
                        if app
                        else "CES writes the conversation tables here"
                    ),
                ),
                project=project,
                name=dataset,
                scope=(f"{app}*",) if app else (),
                whole=not app,
                purpose="conversation logging",
            )
    _app_settings_rest(seeder, data, settings, rel)
    seeder._also = ()


def _app_settings_rest(
    seeder: Seeder, data: dict[str, Any], settings: dict[str, Any], rel: str
) -> None:
    """Audio buckets, DLP templates, client-certificate secrets, CES-created engines."""
    for key, purpose in (
        ("audioRecordingConfig", "audio recordings"),
        ("unredactedAudioRecordingConfig", "audio recordings"),
        ("evaluationAudioRecordingConfig", "evaluation audio"),
    ):
        raw = str((settings.get(key) or {}).get("gcsBucket") or "").strip()
        bucket = raw.removeprefix("gs://").split("/", 1)[0]
        if bucket and bucket != "$env_var":
            seeder.graph.add(
                ids.BUCKET,
                ids.bucket(bucket),
                seeder._ev(
                    rel,
                    raw,
                    f"CES writes {purpose} here (loggingSettings.{key})",
                ),
                name=bucket,
                purpose=purpose,
            )
    redaction = settings.get("redactionConfig") or {}
    for key in ("inspectTemplate", "deidentifyTemplate"):
        if redaction.get(key) and redaction[key] != "$env_var":
            seeder.add_name(
                redaction[key],
                seeder._ev(
                    rel,
                    redaction[key],
                    f"DLP {key} that CES applies to logs (loggingSettings.redactionConfig)",
                ),
            )
    cert = data.get("clientCertificateSettings") or {}
    for key in ("privateKey", "passphrase"):
        if cert.get(key):
            seeder.add_secret_version(
                cert[key],
                seeder._ev(
                    rel,
                    cert[key],
                    f"client certificate {key} (clientCertificateSettings)",
                ),
            )
    for engine in (data.get("dataStoreSettings") or {}).get("engines") or []:
        name = engine.get("name") if isinstance(engine, dict) else engine
        if name and name != "$env_var":
            seeder.add_name(
                str(name),
                seeder._ev(
                    rel,
                    str(name).rsplit("/", 1)[-1],
                    "engine CES created for the app's data store tools (dataStoreSettings)",
                ),
            )


def _add_ref(
    seeder: Seeder, kind: str, rid: str, ev: Evidence, **kwargs: Any
) -> None:
    node = seeder.graph.nodes.get(NodeRef(kind, rid))
    if node is not None:
        # One evidence line per file (the structured pass may have recorded it
        # already), but every table or object the file names joins the scope.
        ev = next((e for e in node.evidence if e.file == ev.file), ev)
    seeder.graph.add(kind, rid, ev, **kwargs)


def seed_text_refs(
    seeder: Seeder, refs: Refs, skip_prefixes: tuple[str, ...]
) -> None:
    def keep(rel: str) -> bool:
        return not rel.startswith(skip_prefixes)

    for url, _host, rel, line in refs.run_urls:
        if keep(rel):
            target = classify_url(url, seeder.ctx)
            _add_ref(
                seeder,
                target.kind,
                target.id,
                Evidence(usage_label(rel, line), rel, line),
                project=target.project,
                location=target.location,
                name=target.name,
                hints=target.hints,
            )
    for bucket, path, rel, line in refs.gcs:
        if not keep(rel):
            continue
        # gs:// values in the app settings are the logging buckets: their
        # objects are conversation recordings, never listed.
        obj = None if rel in _SETTINGS_FILES else path
        templated = bool(obj) and any(c in obj for c in "{}$%*")
        _add_ref(
            seeder,
            ids.BUCKET,
            ids.bucket(bucket),
            Evidence(usage_label(rel, line), rel, line),
            name=bucket,
            scope=(obj,) if obj and not templated else (),
            hints={"templated_objects": [obj]} if templated else None,
        )
    for project, dataset, table, rel, line in refs.bq:
        if keep(rel):
            proj = seeder.ctx.project_key(project)
            _add_ref(
                seeder,
                ids.BQ,
                ids.dataset(seeder.ctx, proj, dataset),
                Evidence(
                    usage_label(rel, line)
                    + (
                        ""
                        if table
                        else ": the code builds queries on this dataset"
                    ),
                    rel,
                    line,
                ),
                project=proj,
                name=dataset,
                scope=(table,) if table else (),
                whole=table is None,
            )
    for project, secret, rel, line in refs.secrets:
        if keep(rel):
            proj = seeder.ctx.project_key(project)
            _add_ref(
                seeder,
                ids.SECRET,
                ids.secret(seeder.ctx, proj, secret),
                Evidence(usage_label(rel, line), rel, line),
                project=proj,
            )
    for ext in refs.other:
        if not keep(ext.file):
            continue
        ev = Evidence(usage_label(ext.file, ext.line), ext.file, ext.line)
        if ext.service in _URL_SERVICES:
            target = classify_url(ext.value, seeder.ctx)
            _add_ref(
                seeder,
                target.kind,
                target.id,
                ev,
                project=target.project,
                location=target.location,
                name=target.name,
                hints=target.hints,
            )
        else:
            resolved = seeder.resolve_name(ext.value)
            if resolved:
                kind, rid, project, location = resolved
                _add_ref(
                    seeder, kind, rid, ev, project=project, location=location
                )
