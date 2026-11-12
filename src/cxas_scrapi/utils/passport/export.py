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

"""`cxas pull --passport` (bundle layout v4): walk, write metadata, scrub.

    graph = ResourceGraph(ctx, default_plugins(), fallback_plugin())
    Seeder(graph, root).<toolsets/tools/app settings/text refs>
    graph.expand()        # follow edges until no new usage-scoped node
    write_nodes(graph)    # README + live config per resource
    scrub                 # ${GCP_PROJECT}, ${GCP_PROJECT_NUMBER} (+ bucket / URL tokens)

Read-only on the source project; never enables an API. A resource that cannot
be read is recorded as not readable (error and missing permission), and so is
a failed read of part of one (a table schema, an IAM policy, the MCP server
config) or of the project; the pull goes on. `strict=True` raises
PassportReadError after writing the bundle when anything could not be read.
"""

from __future__ import annotations

import re
import shlex
import time
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.agent_graph import (
    extract_agent_graph,
    prune_orphan_toolsets,
)
from cxas_scrapi.utils.passport.files import (
    bundle_files,
    read_json,
    resolve_root,
)
from cxas_scrapi.utils.passport.gcp import remote_fetch_allowed
from cxas_scrapi.utils.passport.graph import (
    READ,
    ResourceGraph,
    WalkContext,
)
from cxas_scrapi.utils.passport.http import NotReadable, make_reader
from cxas_scrapi.utils.passport.iam import READ_ROLES
from cxas_scrapi.utils.passport.identities import (
    assign_folders,
    assign_roles,
    write_nodes,
)
from cxas_scrapi.utils.passport.model import Scrubber, token_name
from cxas_scrapi.utils.passport.outputs import ExportState, finish
from cxas_scrapi.utils.passport.plugins import default_plugins, fallback_plugin
from cxas_scrapi.utils.passport.previous import (
    remove_previous_passport,
    restore_source_values,
)
from cxas_scrapi.utils.passport.scan import guess_project_id, scan_agent_files
from cxas_scrapi.utils.passport.scrub import Writer, scrub_agent_files
from cxas_scrapi.utils.passport.seeds import Seeder

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "PassportReadError",
    "run_passport_export",
]


class PassportReadError(Exception):
    """`--strict`: something the agent depends on could not be read (bundle written)."""

    def __init__(self, report: dict[str, Any]) -> None:
        names = ", ".join(
            item["id"]
            + (
                f" ({item['what']})"
                if item.get("what") not in (None, "", "the resource")
                else ""
            )
            for item in report.get("not_readable", [])
        )
        super().__init__(f"resources not readable: {names}")
        self.report = report


def _project_number(ctx: WalkContext, refs_numbers: Any) -> str | None:
    fallback = refs_numbers.most_common(1)[0][0] if refs_numbers else None
    if ctx.live and ctx.reader is not None and ctx.project_id:
        try:
            data = ctx.reader.get(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{ctx.project_id}",
                area="resource_manager",
            )
            if data.get("projectNumber"):
                return str(data["projectNumber"])
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind="resourcemanager.project",
                rid=f"projects/{ctx.project_id}",
                what="project number",
                role=READ_ROLES["project"],
                impact="the number the agent files use was taken instead"
                if fallback
                else "the project number is unknown: values that contain it keep it",
            )
    return fallback


def _orphan_agent_dirs(root: Path, orphans: list[str]) -> list[str]:
    out = []
    for path in sorted((root / "agents").glob("*/*.json")):
        name = str(read_json(path).get("displayName") or path.parent.name)
        if name in orphans:
            out.append(path.parent.name)
    return out


def _app_id(app_name: str | None) -> str | None:
    """`<id>` of projects/p/locations/l/apps/<id>[/versions/v]."""
    m = re.search(r"/apps/([^/]+)", app_name or "")
    return m.group(1) if m else None


def _scrubber(graph: ResourceGraph, ctx: WalkContext) -> Scrubber:
    rewrites: dict[str, str] = {}
    buckets: dict[str, str] = {}
    for node in graph.ordered():
        if node.kind == ids.RUN:
            for host, rewrite in node.hints.get("url_rewrites", []):
                rewrites[host] = rewrite
        elif node.kind == ids.BUCKET:
            name = node.ref.id.rsplit("/", 1)[-1]
            in_name = bool(ctx.project_id and ctx.project_id in name)
            owned = (
                node.extras.get("owned")
                if node.status == READ
                else (True if in_name else None)
            )
            if owned and not in_name:
                buckets[name] = token_name("GCS_BUCKET_", name)
    return Scrubber(ctx.project_id, ctx.project_number, rewrites, buckets)


def _push_command(display: str, location: str, scrub: Scrubber) -> str:
    parts = [
        "cxas push --app-dir .",
        "--project-id <TARGET_PROJECT>",
        f"--location {location}",
        f"--display-name {shlex.quote(display)}",
        "--passport",
    ] + [
        f"--set {token}=<BUCKET>"
        for token in sorted(scrub.bucket_tokens.values())
    ]
    return " \\\n  ".join(parts)


def run_passport_export(
    app_root: str | Path,
    project_id: str | None = None,
    location: str | None = None,
    app_name: str | None = None,
    apps_client: Any = None,
    live_introspect: bool = True,
    *,
    strict: bool = False,
    reader: Any = None,
) -> dict[str, Any]:
    """Turn an exported CES app folder into a passport bundle."""
    started = time.perf_counter()
    root = resolve_root(app_root)
    removed = remove_previous_passport(root)
    app_data = read_json(root / "app.json")
    env_data = read_json(root / "environment.json")
    display = str(app_data.get("displayName") or root.name)
    ces_location = (
        location
        or (
            app_name.split("/")[3]
            if app_name and app_name.count("/") >= 3
            else None
        )
        or "us"
    )

    agent = extract_agent_graph(root, app_data)
    active_toolsets, pruned = prune_orphan_toolsets(root, agent, env_data)
    agent_files = bundle_files(root)
    refs = scan_agent_files(root, agent_files)
    pid = project_id or guess_project_id(refs, app_name)
    if reader is None and remote_fetch_allowed(live_introspect):
        reader = make_reader(apps_client)
    live = bool(live_introspect and reader is not None)
    if live and pid and hasattr(reader, "quota_project"):
        reader.quota_project = pid
    ctx = WalkContext(reader if live else None, pid, None, live)

    t_gcp = time.perf_counter()
    ctx.project_number = _project_number(ctx, refs.numbers)
    restored, still_there = restore_source_values(
        agent_files, pid, ctx.project_number
    )
    if restored:
        refs = scan_agent_files(root, agent_files)
    if still_there:
        ctx.errors.append(
            "the agent files already had passport placeholders ("
            + ", ".join(f"${{{n}}}" for n in still_there)
            + ") from an earlier export whose source values are unknown here: pull the app again"
        )
    graph = ResourceGraph(ctx, default_plugins(), fallback_plugin())
    seeder = Seeder(graph, root)
    used = (
        (agent["referenced_tools"] | agent["referenced_toolsets"])
        if agent["active_agents"]
        else set()
    )
    skipped_tools = seeder.tools(used, env_data)
    seeder.toolsets(env_data)
    seeder.app_settings(app_data, env_data, app_id=_app_id(app_name))
    skip = tuple(f"tools/{d}/" for d in sorted(skipped_tools)) + tuple(
        f"agents/{d}/" for d in _orphan_agent_dirs(root, agent["orphan_agents"])
    )
    seeder.text_refs(refs, skip)
    graph.expand()
    assign_folders(graph)
    identities = assign_roles(graph, ctx)
    gcp_ms = round((time.perf_counter() - t_gcp) * 1000.0, 3)

    scrub = _scrubber(graph, ctx)
    changed_files, portability = scrub_agent_files(root, agent_files, scrub)
    writer = Writer(root, scrub)
    write_nodes(graph, writer, display)
    report = finish(
        ExportState(
            root=root,
            display=display,
            ces_location=ces_location,
            app_data=app_data,
            app_name=app_name,
            agent=agent,
            active_toolsets=active_toolsets,
            pruned=pruned,
            graph=graph,
            seeder=seeder,
            identities=identities,
            scrub=scrub,
            writer=writer,
            agent_rels=[
                str(p.relative_to(root)) for p in agent_files if p.exists()
            ],
            changed_files=changed_files,
            portability=portability,
            removed=removed,
            reader=reader,
            live=live,
            started=started,
            gcp_ms=gcp_ms,
            push_command=_push_command(display, ces_location, scrub),
        )
    )
    if strict and graph.has_unreadable():
        raise PassportReadError(report)
    return report
