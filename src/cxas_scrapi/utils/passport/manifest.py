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

"""`passport/manifest.json` of passport layout v4.

`resources` is keyed by service folder (only the services the agent really
uses appear) and lists every node of the graph with its status, evidence,
dependencies and kind-specific live facts. `placeholders`, `agent` and the
Cloud Run `service`/`region` keys keep the shape `cxas push --passport` reads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.graph import NOT_READABLE, READ
from cxas_scrapi.utils.passport.iam import iam_summary
from cxas_scrapi.utils.passport.model import PASSPORT_DIR_NAME
from cxas_scrapi.utils.passport.plugins.base import stable
from cxas_scrapi.utils.passport.term_style import plural_noun

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, ResourceGraph

SCHEMA_VERSION = "4.0"
BUNDLE_LAYOUT = "passport-v4"
# `what` of a not-readable entry for a resource that could not be read at all.
WHOLE_RESOURCE = "the resource"


def placeholder_help(name: str) -> tuple[str, str]:
    """(what replaces it, how it is set) for a placeholder name."""
    if name == "GCP_PROJECT":
        return (
            "the target Google Cloud project ID",
            "`cxas push --passport --project-id <TARGET_PROJECT>`",
        )
    if name == "GCP_PROJECT_NUMBER":
        return (
            "the target project number",
            "looked up from the project ID by `cxas push --passport` (or `--project-number <NUMBER>`)",
        )
    if name == "BQ_DATASET_ID":
        return (
            "the target BigQuery dataset ID",
            "`cxas push --passport --set BQ_DATASET_ID=<DATASET>`",
        )
    if name == "BQ_TABLE_ID":
        return (
            "the target BigQuery table ID (for CES conversation logging, CES names the table after the target app ID)",
            "`cxas push --passport --set BQ_TABLE_ID=<TABLE>`",
        )
    if name.startswith("GCS_BUCKET_"):
        return (
            "the target bucket name (the source bucket's name does not contain the project ID)",
            f"`cxas push --passport --set {name}=<BUCKET>`",
        )
    if name.startswith("CLOUD_RUN_URL_"):
        return (
            "the URL of the same Cloud Run service in the target project",
            f"derived from the project number by `cxas push --passport` (or `--set {name}=<URL>`)",
        )
    if name.startswith("REDACTED_"):
        return (
            "a credential the passport does not carry (only in passport/ files)",
            "not needed for the push; fill it in if you recreate the resource",
        )
    return (
        "a value from the source",
        f"`cxas push --passport --set {name}=<VALUE>`",
    )


def placeholders_index(
    occurrences: dict[str, list[tuple[str, int, str]]],
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, occ in sorted(occurrences.items()):
        replace_with, how = placeholder_help(name)
        out[name] = {
            "replace_with": replace_with,
            "how_set": how,
            "required_for_push": any(
                not f.startswith(f"{PASSPORT_DIR_NAME}/") for f, _, _ in occ
            ),
            "occurrences": [{"file": f, "line": n} for f, n, _ in occ],
        }
    return out


def node_entry(
    node: Node, graph: ResourceGraph, files: list[str]
) -> dict[str, Any]:
    plugin = graph.plugin_for(node)
    ctx = graph.ctx
    entry: dict[str, Any] = {
        "kind": node.kind,
        "product": plugin.service_of(node),
        "name": node.name,
        "id": node.ref.id,
        "project": node.project,
        "location": node.location,
        "cross_project": bool(node.project)
        and not ctx.is_source(node.project)
        and node.project != "_",
        "status": node.status,
        "folder": f"{PASSPORT_DIR_NAME}/{node.folder}",
        "files": files,
        "used_by": [ev.text for ev in node.evidence],
        "depends_on": [
            {"kind": ref.kind, "id": ref.id, "relation": rel}
            for ref, rel in node.depends_on
        ],
    }
    if node.kind == ids.RUN:
        parts = node.ref.id.split("/")
        entry["service"], entry["region"] = parts[5], parts[3]
    if node.status == NOT_READABLE:
        entry.update(
            error=node.error,
            error_category=node.error_category,
            missing_permission=node.missing_permission,
        )
    if node.status == READ:
        entry["live"] = stable(plugin.summary(node))
        if node.iam is not None:
            entry["iam"] = iam_summary(node.iam)
    parts = graph.failures_of(node.ref)
    if parts:
        entry["not_readable_parts"] = [
            {
                "what": f.what,
                "id": f.id,
                "error": f.error,
                "error_category": f.category,
                "missing_permission": f.missing_permission,
                "impact": f.impact,
            }
            for f in parts
        ]
    if node.notes:
        entry["notes"] = node.notes
    return entry


def resources_section(
    graph: ResourceGraph, files_by_folder: dict[str, list[str]]
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for node in graph.ordered():
        folder = graph.plugin_for(node).folder_of(node)
        out.setdefault(folder, []).append(
            node_entry(node, graph, files_by_folder.get(node.folder, []))
        )
    return out


def not_readable_section(graph: ResourceGraph) -> list[dict[str, Any]]:
    """Resources, parts of resources and project reads that failed."""
    out: list[dict[str, Any]] = [
        {
            "kind": n.kind,
            "id": n.ref.id,
            "what": WHOLE_RESOURCE,
            "folder": f"{PASSPORT_DIR_NAME}/{n.folder}",
            "error": n.error,
            "error_category": n.error_category,
            "missing_permission": n.missing_permission,
            "used_by": [ev.text for ev in n.evidence],
        }
        for n in graph.ordered()
        if n.status == NOT_READABLE
    ]
    for f in graph.ctx.failures:
        owner = graph.nodes.get(f.owner) if f.owner else None
        out.append(
            {
                "kind": f.kind,
                "id": f.id,
                "what": f.what,
                "resource": owner.ref.id if owner else None,
                "folder": f"{PASSPORT_DIR_NAME}/{owner.folder}"
                if owner
                else None,
                "error": f.error,
                "error_category": f.category,
                "missing_permission": f.missing_permission,
                "used_by": [ev.text for ev in owner.evidence] if owner else [],
                "impact": f.impact,
            }
        )
    return out


def graph_section(graph: ResourceGraph) -> dict[str, Any]:
    edges = [
        {"from": n.ref.id, "to": ref.id, "relation": rel}
        for n in graph.ordered()
        for ref, rel in n.depends_on
    ]
    seeds = [
        n.ref.id
        for n in graph.ordered()
        if any(ev.parent is None for ev in n.evidence)
    ]
    return {"nodes": len(graph.nodes), "seeds": seeds, "edges": edges}


def counts_by_service(graph: ResourceGraph) -> list[str]:
    """["BigQuery (2 datasets)", ...] in plugin order."""
    counts: dict[tuple[str, str], int] = {}
    for node in graph.ordered():
        plugin = graph.plugin_for(node)
        key = (plugin.service_of(node), plugin.noun_of(node))
        counts[key] = counts.get(key, 0) + 1
    return [
        f"{service} ({count} {plural_noun(noun, count)})"
        for (service, noun), count in counts.items()
    ]
