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

"""MCP Toolbox server config (tools.yaml): parsing and credential redaction."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

import yaml

# MCP Toolbox tool kinds that run any SQL over the source's datasets (so every
# table of an allowed dataset is in use), and the source kinds per service.
GENERIC_BQ_TOOL_KINDS = (
    "bigquery-execute-sql",
    "bigquery-list-table-ids",
    "bigquery-get-table-info",
    "bigquery-conversational-analytics",
    "bigquery-forecast",
    "bigquery-analyze-contribution",
    "bigquery-search-catalog",
)
GCS_SOURCE_KINDS = {"cloud-storage", "gcs", "cloud_storage"}
BQ_SOURCE_KINDS = {"bigquery"}

# Credential-like keys in an MCP server config (matched as a whole key).
CREDENTIAL_KEY_RE = re.compile(
    r"(?i)^(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|id[_-]?token|api[_-]?key|apikey|private[_-]?key|credentials?|credentials[_-]?json|"
    r"service[_-]?account[_-]?key|connection[_-]?string|conn[_-]?str|dsn|bearer|secret[_-]?key|"
    r"access[_-]?key|access[_-]?key[_-]?id|secret[_-]?access[_-]?key)$"
)
_YAML_KEY_LINE_RE = re.compile(
    r"^(?P<lead>\s*(?:-\s+)?)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*:\s*)(?P<value>.*?)\s*$"
)
URL_PASSWORD_RE = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^:/@\s\"']+):(?P<password>[^@/\s\"']+)@"
)


def redact_credentials(text: str) -> str:
    """Replace credential-like values of a YAML config with `${REDACTED_...}` placeholders.

    A credential key gets `key: "${REDACTED_<KEY>}"` (a double-quoted scalar, so
    the YAML stays valid whatever value fills it in once escaped); a password
    inside a URL gets `${REDACTED_URL_PASSWORD}` in place (the value must be
    percent-encoded). PLACEHOLDERS.md lists the placeholders found in the
    written file.
    """
    lines = text.split("\n")
    out: list[str] = []
    used: Counter = Counter()

    def _placeholder(key: str) -> str:
        base = (
            "REDACTED_" + re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper()
        )
        used[base] += 1
        return (
            "${" + (base if used[base] == 1 else f"{base}_{used[base]}") + "}"
        )

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        m = _YAML_KEY_LINE_RE.match(line)
        if (
            m
            and CREDENTIAL_KEY_RE.match(m.group("key"))
            and not line.lstrip().startswith("#")
        ):
            value = m.group("value")
            stripped = value.strip().strip("'\"")
            if value and not re.fullmatch(
                r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", stripped
            ):
                placeholder = _placeholder(m.group("key"))
                indent = len(line) - len(line.lstrip())
                if re.fullmatch(r"[|>][-+0-9]*", value.strip()):
                    idx += 1
                    while idx < len(lines) and (
                        not lines[idx].strip()
                        or len(lines[idx]) - len(lines[idx].lstrip()) > indent
                    ):
                        idx += 1
                else:
                    idx += 1
                out.append(
                    f'{m.group("lead")}{m.group("key")}{m.group("sep")}"{placeholder}"'
                )
                continue
        if URL_PASSWORD_RE.search(line) and not line.lstrip().startswith("#"):
            placeholder = _placeholder("url_password")
            line = URL_PASSWORD_RE.sub(
                lambda mm, p=placeholder: f"{mm.group('prefix')}:{p}@", line
            )
        out.append(line)
        idx += 1
    return "\n".join(out)


def parse_mcp_config(
    text: str,
) -> (
    tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        dict[str, list[str]],
    ]
    | None
):
    """(sources, tools, toolsets) of an MCP Toolbox config, or None if it is not one.

    Supports the `sources:` / `tools:` / `toolsets:` layout and the multi-document
    layout (`kind: sources` + `name` + `type` per document).
    """
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return None
    if not docs or not all(isinstance(d, dict) for d in docs):
        return None
    sources: dict[str, dict[str, Any]] = {}
    tools: dict[str, dict[str, Any]] = {}
    toolsets: dict[str, list[str]] = {}
    section_keys = {
        "sources",
        "tools",
        "toolsets",
        "authServices",
        "authSources",
        "prompts",
    }
    if len(docs) == 1 and section_keys & set(docs[0]):
        doc = docs[0]
        for name, src in (doc.get("sources") or {}).items():
            if isinstance(src, dict):
                sources[str(name)] = {
                    **src,
                    "kind": str(src.get("kind") or src.get("type") or ""),
                }
        for name, tool in (doc.get("tools") or {}).items():
            if isinstance(tool, dict):
                tools[str(name)] = {
                    **tool,
                    "kind": str(tool.get("kind") or tool.get("type") or ""),
                }
        for name, items in (doc.get("toolsets") or {}).items():
            if isinstance(items, list):
                toolsets[str(name)] = [str(i) for i in items]
        return sources, tools, toolsets
    matched = False
    for doc in docs:
        section = str(doc.get("kind") or "")
        name = str(doc.get("name") or "")
        if section == "sources" and name:
            sources[name] = {**doc, "kind": str(doc.get("type") or "")}
            matched = True
        elif section == "tools" and name:
            tools[name] = {**doc, "kind": str(doc.get("type") or "")}
            matched = True
        elif section == "toolsets" and name:
            toolsets[name] = [str(t) for t in doc.get("tools") or []]
            matched = True
        elif section in section_keys:
            matched = True
    return (sources, tools, toolsets) if matched else None


def is_mcp_toolbox_image(image: str | None) -> bool:
    image = image or ""
    return "toolbox" in image and any(
        hint in image
        for hint in (
            "database-toolbox",
            "genai-toolbox",
            "/toolbox:",
            "/toolbox@",
        )
    )
