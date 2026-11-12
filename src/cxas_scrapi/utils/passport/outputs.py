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

"""Last step of a v4 export: PLACEHOLDERS.md, manifest.json, the leak check
and the summary `cxas pull` prints."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import manifest
from cxas_scrapi.utils.passport.files import bundle_files, read_text
from cxas_scrapi.utils.passport.guide import kept_names, render_guide, tree_rows
from cxas_scrapi.utils.passport.http import RETRY_STATUSES
from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PASSPORT_LEDGER_NAME,
    PASSPORT_MANIFEST_NAME,
    PLACEHOLDERS_GUIDE_NAME,
)
from cxas_scrapi.utils.passport.scrub import scan_occurrences

if TYPE_CHECKING:
    from pathlib import Path

    from cxas_scrapi.utils.passport.graph import ResourceGraph
    from cxas_scrapi.utils.passport.model import Scrubber
    from cxas_scrapi.utils.passport.scrub import Writer
    from cxas_scrapi.utils.passport.seeds import Seeder


@dataclass
class ExportState:
    """Everything the export collected before the guide and the manifest."""

    root: Path
    display: str
    ces_location: str
    app_data: dict[str, Any]
    app_name: str | None
    agent: dict[str, Any]
    active_toolsets: list[str]
    pruned: list[dict[str, Any]]
    graph: ResourceGraph
    seeder: Seeder
    identities: list[dict[str, Any]]
    scrub: Scrubber
    writer: Writer
    agent_rels: list[str]
    changed_files: list[str]
    portability: list[dict[str, Any]]
    removed: list[str]
    reader: Any
    live: bool
    started: float
    gcp_ms: float
    push_command: str


def _warnings(s: ExportState) -> list[str]:
    """Notes of the walk that are not failed reads (those are `not_readable`)."""
    out = [s.scrub(w) for w in s.graph.ctx.errors + s.seeder.notes]
    if s.seeder.unused_tools:
        out.append(
            "tools no active agent uses (their resources are not followed): "
            + ", ".join(sorted(s.seeder.unused_tools))
        )
    return out


def _introspection(s: ExportState, total_ms: float) -> dict[str, Any]:
    calls = list(getattr(s.reader, "calls", []) or []) if s.live else []
    return {
        "live": s.live,
        "read_only": all(
            m == "GET" or u.split("?", 1)[0].endswith(":getIamPolicy")
            for m, u, _ in calls
        ),
        "api_calls": len(calls),
        "transient_errors_retried": [
            {"url": s.scrub(u.split("?", 1)[0]), "status": st}
            for _, u, st in calls
            if st is None or st in RETRY_STATUSES
        ],
        "removed_from_previous_pull": [
            r for r in s.removed if not (s.root / r.rstrip("/")).exists()
        ],
        "timings_ms": {
            "total_passport_export_ms": total_ms,
            "total_gcp_introspection_ms": s.gcp_ms,
            "per_plugin": dict(sorted(s.graph.ctx.timings_ms.items())),
            "per_api": dict(
                sorted((getattr(s.reader, "timings_ms", {}) or {}).items())
            )
            if s.live
            else {},
        },
    }


def _document(
    s: ExportState, occurrences: dict, redactions: dict, warnings: list[str]
) -> dict[str, Any]:
    files_by_folder: dict[str, list[str]] = {}
    for item in s.writer.files:
        parts = item["path"].split("/")
        files_by_folder.setdefault("/".join(parts[1:3]), []).append(
            "/".join(parts[3:])
        )
    ctx = s.graph.ctx
    return {
        "schema_version": manifest.SCHEMA_VERSION,
        "bundle_layout": manifest.BUNDLE_LAYOUT,
        "generated_by": "cxas pull --passport",
        "app": {
            "display_name": s.display,
            "root_agent": s.agent["root_agent"] or None,
            "model": (s.app_data.get("modelSettings") or {}).get("model")
            or None,
            "ces_location": s.ces_location,
        },
        "source": {
            "project_id": ctx.project_id,
            "project_number": ctx.project_number,
            "location": s.ces_location,
        },
        "agent": {
            "active_agents": s.agent["active_agents"],
            "orphan_agents": s.agent["orphan_agents"],
            "active_toolsets": s.active_toolsets,
            "pruned_orphan_toolsets": s.pruned,
            "unused_tools": sorted(s.seeder.unused_tools),
        },
        "placeholders": manifest.placeholders_index(occurrences),
        "redacted_values": {
            name: [{"file": f, "line": n} for f, n, _ in occ]
            for name, occ in sorted(redactions.items())
        },
        "portability_changes": s.portability,
        "parameterized_files": s.changed_files,
        "summary": manifest.counts_by_service(s.graph),
        "not_readable": manifest.not_readable_section(s.graph),
        "warnings": warnings,
        "resources": manifest.resources_section(s.graph, files_by_folder),
        "identities": s.identities,
        "graph": manifest.graph_section(s.graph),
        "push": {"command": s.push_command.replace(" \\\n  ", " ")},
        "files": [
            *s.writer.files,
            {"path": PLACEHOLDERS_GUIDE_NAME, "purpose": "human guide"},
        ],
    }


def _force_scrub(s: ExportState, guide_path: Path) -> list[str]:
    """Last check: no raw source project ID or number anywhere in the bundle."""
    leftovers: list[str] = []
    paths = [
        *bundle_files(s.root),
        *(
            p
            for p in (s.root / PASSPORT_DIR_NAME).rglob("*")
            if p.is_file() and not p.is_symlink()
        ),
        guide_path,
    ]
    for path in paths:
        rel = str(path.relative_to(s.root))
        text = read_text(path)
        if (
            rel.endswith(PASSPORT_LEDGER_NAME)
            or text is None
            or not s.scrub.leftovers(text)
        ):
            continue
        path.write_text(s.scrub.force(text), encoding="utf-8")
        leftovers.append(rel)
    return leftovers


def finish(s: ExportState) -> dict[str, Any]:
    """Write PLACEHOLDERS.md and manifest.json; return the `cxas pull` summary."""
    ctx = s.graph.ctx
    config_rels = [
        w["path"] for w in s.writer.files if not w["path"].endswith("README.md")
    ]
    occurrences = scan_occurrences(s.root, s.agent_rels)
    config_occ = scan_occurrences(s.root, config_rels)
    for name, occ in config_occ.items():
        if not name.startswith("REDACTED_") and name not in occurrences:
            occurrences[name] = occ
    redactions = {
        name: occ
        for name, occ in config_occ.items()
        if name.startswith("REDACTED_")
    }
    texts = {
        rel: read_text(s.root / rel) or "" for rel in s.agent_rels + config_rels
    }
    kept = kept_names(
        s.graph,
        texts,
        tuple(v for v in (ctx.project_id, ctx.project_number) if v),
    )
    warnings = _warnings(s)
    guide_path = s.root / PLACEHOLDERS_GUIDE_NAME
    guide = render_guide(
        app_display_name=s.display,
        graph=s.graph,
        identities=s.identities,
        occurrences=occurrences,
        redactions=redactions,
        portability=s.portability,
        kept=kept,
        push_command=s.push_command,
        tree=tree_rows(s.agent_rels, list(s.writer.files)),
        warnings=warnings,
        live=s.live,
    )
    guide_path.write_text(s.scrub(guide), encoding="utf-8")
    document = _document(s, occurrences, redactions, warnings)
    total_ms = round((time.perf_counter() - s.started) * 1000.0, 3)
    document["introspection"] = _introspection(s, total_ms)
    manifest_path = s.root / PASSPORT_DIR_NAME / PASSPORT_MANIFEST_NAME
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        s.scrub(json.dumps(document, indent=2) + "\n"), encoding="utf-8"
    )
    leftovers = _force_scrub(s, guide_path)
    return {
        "bundle_layout": manifest.BUNDLE_LAYOUT,
        "app_root": str(s.root),
        "app_display_name": s.display,
        "root_agent": s.agent["root_agent"],
        "active_agents": s.agent["active_agents"],
        "active_toolsets": s.active_toolsets,
        "pruned_orphans": [p["name"] for p in s.pruned],
        "pruned_orphan_details": s.pruned,
        "parameterized_files": s.changed_files,
        "placeholders": sorted(occurrences),
        "passport_dir": str(s.root / PASSPORT_DIR_NAME),
        "manifest_path": str(manifest_path),
        "placeholders_guide_path": str(guide_path),
        "generated_artifacts": [
            w["path"].removeprefix(f"{PASSPORT_DIR_NAME}/")
            for w in s.writer.files
        ]
        + [PASSPORT_MANIFEST_NAME],
        "services_discovered": manifest.counts_by_service(s.graph),
        "resources": [
            {
                "kind": n.kind,
                "service": s.graph.plugin_for(n).service_of(n),
                "noun": s.graph.plugin_for(n).noun_of(n),
                "name": s.scrub(n.name)
                if n.name
                else s.scrub(n.ref.id.rsplit("/", 1)[-1]),
                "id": s.scrub(n.ref.id),
                "status": n.status,
                "folder": f"{PASSPORT_DIR_NAME}/{n.folder}",
            }
            for n in s.graph.ordered()
        ],
        "not_readable": json.loads(
            s.scrub(json.dumps(document["not_readable"]))
        ),
        "gcp_introspection_errors": warnings,
        "live_introspect": s.live,
        "read_only": document["introspection"]["read_only"],
        "raw_values_force_scrubbed": leftovers,
        "legacy_artifacts_removed": document["introspection"][
            "removed_from_previous_pull"
        ],
        "latency_ms": {
            "total_passport_export_ms": total_ms,
            "total_gcp_introspection_ms": s.gcp_ms,
        },
        "timings_per_plugin_ms": dict(sorted(ctx.timings_ms.items())),
    }
