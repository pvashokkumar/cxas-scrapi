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

"""Names, placeholders and the scrubber of the `cxas pull --passport` export.

The export reads raw source values (real project ID and number, bucket names,
URLs) and writes every file through `Scrubber`, so that placeholders replace
project-specific values in one place. `BqDataset` and `BqTable` feed the
BigQuery DDL of `schema.sql`; `RunService` and `McpConfig` hold what the Cloud
Run plugin reads from a service spec and from its MCP server config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

PASSPORT_DIR_NAME = "passport"
PASSPORT_MANIFEST_NAME = "manifest.json"
PLACEHOLDERS_GUIDE_NAME = "PLACEHOLDERS.md"
PASSPORT_LEDGER_NAME = "ledger.jsonl"

GCP_PROJECT_TOKEN = "${GCP_PROJECT}"
GCP_PROJECT_NUMBER_TOKEN = "${GCP_PROJECT_NUMBER}"
BQ_DATASET_ID_TOKEN = "${BQ_DATASET_ID}"
BQ_TABLE_ID_TOKEN = "${BQ_TABLE_ID}"

# Placeholder names the passport writes. Push replaces exactly these; any
# other `${...}` text in the agent is left alone.
PLACEHOLDER_NAME_RE = re.compile(
    r"\$\{(GCP_PROJECT|GCP_PROJECT_NUMBER|BQ_DATASET_ID|BQ_TABLE_ID|GCS_BUCKET_[A-Z0-9_]+|CLOUD_RUN_URL_[A-Z0-9_]+|REDACTED_[A-Z0-9_]+)\}"
)


def token_name(prefix: str, value: str) -> str:
    """`GCS_BUCKET_MY_BUCKET`-style placeholder name for a resource name."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return f"{prefix}{cleaned or 'VALUE'}"


@dataclass
class BqTable:
    name: str
    kind: str = "TABLE"  # TABLE, VIEW, MATERIALIZED_VIEW, EXTERNAL, SNAPSHOT
    resource: dict[str, Any] | None = None  # live table resource (schema etc.)
    ddl_name: str | None = None  # placeholder name in schema.sql when set
    rows: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BqDataset:
    project: str
    dataset: str
    purpose: str = "data"  # "data" or "conversation_export"
    location: str | None = None
    resource: dict[str, Any] | None = None  # live dataset resource
    tables: dict[str, BqTable] = field(default_factory=dict)


@dataclass
class McpConfig:
    """An MCP server config file (tools.yaml) mounted from Secret Manager."""

    secret: str
    version: str
    mount_file: str
    text: str = ""  # credential-like values already redacted
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    toolsets: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class RunService:
    project: str
    region: str
    name: str
    spec: dict[str, Any] | None = None  # sanitized Knative service
    service_account: str | None = (
        None  # None: the default compute service account
    )
    image: str | None = None
    env: list[dict[str, Any]] = field(default_factory=list)
    secret_volumes: list[dict[str, Any]] = field(default_factory=list)
    is_mcp_toolbox: bool = False


@dataclass
class ExternalRef:
    """A reference to another kind of Google Cloud resource (Vertex AI Search, Cloud Functions, ...) the walk resolves."""

    service: str
    value: str
    file: str
    line: int


class Scrubber:
    """Replaces source-project values with placeholders in text.

    Order matters: Cloud Run URLs in the `<service>-<hash>-<region code>.a.run.app`
    form (rewritten to an equivalent URL that the project number determines,
    or to a placeholder), bucket names without the project ID, pinned secret
    versions, then the project number and the project ID themselves.
    """

    def __init__(
        self,
        project_id: str | None,
        project_number: str | None,
        url_rewrites: dict[str, str] | None = None,
        bucket_tokens: dict[str, str] | None = None,
    ) -> None:
        self.project_id = project_id or None
        self.project_number = project_number or None
        # host -> replacement for "https://<host>" (a URL or "${TOKEN}")
        self.url_rewrites = dict(url_rewrites or {})
        self.bucket_tokens = dict(bucket_tokens or {})  # bucket -> token name
        self._id_re = (
            re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(self.project_id)}(?![A-Za-z0-9_])"
            )
            if self.project_id
            else None
        )
        self._num_re = (
            re.compile(rf"(?<![0-9]){re.escape(self.project_number)}(?![0-9])")
            if self.project_number
            else None
        )
        # Cloud Functions image names spell the project ID with doubled hyphens
        # (`my--project__us--central1__fn`); that spelling names the project too.
        self._encoded_id = (
            self.project_id.replace("-", "--")
            if self.project_id and "-" in self.project_id
            else None
        )
        self._encoded_re = (
            re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(self._encoded_id)}(?![A-Za-z0-9])"
            )
            if self._encoded_id
            else None
        )
        self._bucket_res = [
            (
                re.compile(
                    rf"(gs://|storage\.googleapis\.com/|storage\.cloud\.google\.com/){re.escape(name)}(?![A-Za-z0-9._-])"
                ),
                re.compile(rf"(?P<q>[\"']){re.escape(name)}(?P=q)"),
                re.compile(
                    rf"(?m)^(?P<lead>\s*(?:-\s+|[A-Za-z0-9_]+:\s+)){re.escape(name)}\s*$"
                ),
                token,
            )
            for name, token in sorted(
                self.bucket_tokens.items(), key=lambda kv: -len(kv[0])
            )
        ]

    def __call__(self, text: str) -> str:
        out = text
        for host, replacement in sorted(
            self.url_rewrites.items(), key=lambda kv: -len(kv[0])
        ):
            out = re.sub(
                rf"https?://{re.escape(host)}(?![A-Za-z0-9.-])",
                lambda _m, r=replacement: r,
                out,
            )
        for uri_re, quoted_re, yaml_re, token in self._bucket_res:
            ph = "${" + token + "}"
            out = uri_re.sub(lambda m, ph=ph: m.group(1) + ph, out)
            out = quoted_re.sub(
                lambda m, ph=ph: m.group("q") + ph + m.group("q"), out
            )
            out = yaml_re.sub(lambda m, ph=ph: m.group("lead") + ph, out)
        out = pin_secret_versions_to_latest(out)
        if self._num_re is not None:
            out = self._num_re.sub(GCP_PROJECT_NUMBER_TOKEN, out)
        if self._encoded_re is not None:
            out = self._encoded_re.sub(GCP_PROJECT_TOKEN, out)
        if self._id_re is not None:
            out = self._id_re.sub(GCP_PROJECT_TOKEN, out)
        return out

    def leftovers(self, text: str) -> list[str]:
        """Raw source values still present in `text` (e.g. inside a longer name)."""
        found = []
        if self.project_id and self.project_id in text:
            found.append(self.project_id)
        if self._encoded_id and self._encoded_id in text:
            found.append(self._encoded_id)
        if self._num_re is not None and self._num_re.search(text):
            found.append(str(self.project_number))
        return found

    def force(self, text: str) -> str:
        """Last-resort replacement of raw source values that `__call__` left."""
        out = self(text)
        if self._encoded_id:
            out = out.replace(self._encoded_id, GCP_PROJECT_TOKEN)
        if self.project_id:
            out = out.replace(self.project_id, GCP_PROJECT_TOKEN)
        return out


_PINNED_SECRET_VERSION_RE = re.compile(
    r"(projects/[^/\s\"'`]+/secrets/[A-Za-z0-9_-]+/versions/)([0-9]+)(?![0-9A-Za-z_-])"
)


def pin_secret_versions_to_latest(text: str) -> str:
    """`.../secrets/<name>/versions/<n>` -> `.../versions/latest` (versions do not carry over)."""
    return _PINNED_SECRET_VERSION_RE.sub(lambda m: m.group(1) + "latest", text)


def has_pinned_secret_version(text: str) -> bool:
    return bool(_PINNED_SECRET_VERSION_RE.search(text))
