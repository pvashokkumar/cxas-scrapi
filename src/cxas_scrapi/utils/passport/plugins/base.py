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

"""Plugin contract and the README every resource folder gets.

A plugin handles one resource kind:
    fetch(node, ctx)    read the live config (raise NotReadable on failure)
    details(node, ctx)  read what depends on the usage scope (tables, objects)
    edges(node, ctx)    runtime dependencies found in the live config
    files(node, ctx)    {file name: (content, purpose)} next to the README
    facts(node)         key settings for the README and the manifest
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.graph import (
    EXTERNAL,
    NOT_READABLE,
    OFFLINE,
    READ,
)
from cxas_scrapi.utils.passport.iam import READ_ROLES, visible
from cxas_scrapi.utils.passport.render import md_cell, md_code

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import (
        Edge,
        Node,
        ResourceGraph,
        WalkContext,
    )

_PERSON_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@(?![A-Za-z0-9.-]*gserviceaccount\.com$)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)
STATUS_TEXT = {
    READ: "read live from the source project",
    NOT_READABLE: "NOT READABLE during the pull (see below)",
    OFFLINE: "not read (the pull ran with --no-live-introspect)",
    EXTERNAL: "not read: outside Google Cloud, or a kind the passport has no reader for",
}


def without_people(value: Any) -> Any:
    """`value` with every string that is a person's email replaced by `<user>`."""
    if isinstance(value, dict):
        return {k: without_people(v) for k, v in value.items()}
    if isinstance(value, list):
        return [without_people(v) for v in value]
    if isinstance(value, str) and _PERSON_EMAIL_RE.match(value):
        return "<user>"
    return value


def dump_json(value: Any) -> str:
    """JSON text of a live config, keys sorted: APIs return maps (labels,
    annotations, ...) in a different order on each read, and two pulls of an
    unchanged agent must write the same files."""
    return json.dumps(without_people(value), indent=2, sort_keys=True) + "\n"


def stable(value: Any) -> Any:
    """`value` with the keys of every nested dict sorted (same reason)."""
    return json.loads(json.dumps(value, sort_keys=True))


class Plugin:
    """Base plugin; subclasses set the class attributes and override hooks."""

    kind = ""
    service = ""  # e.g. "BigQuery"
    noun = ""  # e.g. "dataset"
    folder = ""  # passport/<folder>/<resource>/
    read_role: str | None = None
    readable = True

    @property
    def timing_area(self) -> str:
        return self.kind or "generic"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        raise NotImplementedError

    def details(self, node: Node, ctx: WalkContext) -> None:
        return None

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        return []

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        return {}

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        return []

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        return node.name

    def service_of(self, node: Node) -> str:
        return self.service

    def noun_of(self, node: Node) -> str:
        return self.noun

    def folder_of(self, node: Node) -> str:
        return self.folder

    def can_read(self, node: Node) -> bool:
        return self.readable

    def read_role_of(self, node: Node) -> str | None:
        return self.read_role or READ_ROLES.get(node.kind)

    def label_of(self, node: Node) -> str:
        return f"{self.service_of(node)} {self.noun_of(node)} `{node.name}`"

    def summary(self, node: Node) -> dict[str, Any]:
        """Kind-specific fields of the manifest entry (snake_case keys)."""
        out = {}
        for label, value in self.facts(node):
            if value in (None, "", []):
                continue
            key = re.sub(r"\([^)]*\)", "", label.lower())
            out[re.sub(r"[^a-z0-9]+", "_", key).strip("_")] = value
        return out


def _value_text(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(md_code(v) for v in value) if value else "none"
    if isinstance(value, dict):
        return md_code(json.dumps(value, sort_keys=True))
    return md_code(value)


def render_readme(
    plugin: Plugin,
    node: Node,
    graph: ResourceGraph,
    file_purposes: dict[str, str],
    app_display_name: str,
) -> str:
    """README.md of a resource folder: status, use, settings, IAM, files."""
    lines = [
        f"# {plugin.service_of(node)} {plugin.noun_of(node)}: `{node.name}`",
        "",
        f'Used by the CES agent "{app_display_name}". Generated by '
        "`cxas pull --passport`: metadata only (live settings and schemas, never data).",
        "",
        "| | |",
        "|---|---|",
        f"| Resource | {md_code(node.ref.id)} |",
        f"| Kind | {md_code(node.kind)} |",
    ]
    if node.project:
        lines.append(f"| Project | {md_code(node.project)} |")
    if node.location:
        lines.append(f"| Location | {md_code(node.location)} |")
    lines.append(f"| Status | {STATUS_TEXT.get(node.status, node.status)} |")
    lines.append("")
    parts = graph.failures_of(node.ref)
    if node.status == NOT_READABLE or parts:
        lines += ["## Not readable", ""]
    if node.status == NOT_READABLE:
        lines += [
            f"- Error: {md_cell(node.error or '')}",
            f"- Missing: {md_cell(node.missing_permission or 'unknown')}",
        ]
    for part in parts:
        lines.append(
            f"- {md_cell(part.what)}: {md_cell(part.error)} (missing: "
            f"{md_cell(part.missing_permission or 'unknown')})"
            + (f". Consequence: {md_cell(part.impact)}" if part.impact else "")
        )
    if node.status == NOT_READABLE or parts:
        lines.append("")
    lines += ["## Why the agent depends on it", ""]
    for ev in node.evidence:
        lines.append(f"- {ev.text}")
    lines.append("")
    deps = [(graph.nodes.get(ref), rel) for ref, rel in node.depends_on]
    if deps:
        lines += ["## What it needs to run", ""]
        for dep, relation in deps:
            if dep is not None:
                target = graph.plugin_for(dep).label_of(dep)
                lines.append(
                    f"- {relation}: {target} (`passport/{dep.folder}/`)"
                )
        lines.append("")
    facts = [(k, v) for k, v in plugin.facts(node) if v not in (None, "")]
    if facts:
        lines += ["## Settings", "", "| Setting | Value |", "|---|---|"]
        lines += [f"| {md_cell(k)} | {_value_text(v)} |" for k, v in facts]
        lines.append("")
    if node.iam is not None:
        shown, hidden = visible(node.iam)
        lines += ["## IAM on this resource", ""]
        if shown:
            lines += ["| Role | Member |", "|---|---|"]
            lines += [
                f"| {md_code(b.role)} | {md_code(b.member)}"
                + (
                    f" (condition: {md_cell(b.condition)})"
                    if b.condition
                    else ""
                )
                + " |"
                for b in sorted(shown, key=lambda b: (b.role, b.member))
            ]
        else:
            lines.append(
                "No service account or public principal holds a role here."
            )
        if hidden:
            lines += [
                "",
                f"{hidden} more binding(s) of people or groups are not listed.",
            ]
        lines.append("")
    for note in node.notes:
        lines.append(f"> {note}")
    if node.notes:
        lines.append("")
    if file_purposes:
        lines += ["## Files", ""]
        lines += [
            f"- `{name}`: {purpose}" for name, purpose in file_purposes.items()
        ]
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
