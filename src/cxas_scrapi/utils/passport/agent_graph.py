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

"""Agent graph and orphan toolset pruning shared by `pull --passport` and `push --passport`."""

from __future__ import annotations

import re
import shutil
from collections import deque
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.files import (
    read_json,
    read_text,
    safe_bundle_file,
    write_json,
)

if TYPE_CHECKING:
    from pathlib import Path

AGENT_REF_RE = re.compile(r"\{@AGENT:\s*([^}]+?)\s*\}")
TOOL_REF_RE = re.compile(r"\{@(?:TOOL|TOOLSET):\s*([^}]+?)\s*\}")


def _refs(data: dict[str, Any], key: str, fields: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for item in data.get(key, []) or []:
        if isinstance(item, str) and item.strip():
            found.append(item.strip())
        elif isinstance(item, dict):
            for f in fields:
                val = item.get(f)
                if isinstance(val, str) and val.strip():
                    found.append(val.strip())
                    if key != "toolsets":
                        break
    return found


def extract_agent_graph(
    root: Path, app_data: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Walk the agent graph from `rootAgent`: active agents and what they reference."""
    if app_data is None:
        app_data = read_json(root / "app.json")
    root_agent_name = str(app_data.get("rootAgent") or "").strip()
    agents_dir = root / "agents"
    agents_by_key: dict[str, dict[str, Any]] = {}
    alias: dict[str, str] = {}

    if agents_dir.is_dir():
        for agent_dir in sorted(agents_dir.iterdir()):
            if not agent_dir.is_dir() or agent_dir.name.startswith("_"):
                continue
            json_files = sorted(agent_dir.glob("*.json"))
            if not json_files:
                continue
            aj_path = json_files[0]
            data = read_json(aj_path)
            disp = str(data.get("displayName") or agent_dir.name).strip()
            aid = str(data.get("name") or "").strip()
            inst_rel = str(data.get("instruction") or "").strip()
            inst_path = (
                (
                    safe_bundle_file(root, inst_rel)
                    or safe_bundle_file(root, inst_rel, base=agent_dir)
                )
                if inst_rel
                else safe_bundle_file(
                    root, f"agents/{agent_dir.name}/instruction.txt"
                )
            )
            inst_text = (
                (read_text(inst_path) or "") if inst_path is not None else ""
            )
            agents_by_key[disp] = {
                "displayName": disp,
                "dir_name": agent_dir.name,
                "id": aid,
                "json_path": aj_path,
                "inst_path": inst_path,
                "inst_text": inst_text,
                "child_refs": _refs(
                    data, "childAgents", ("agent", "displayName", "name")
                )
                + _refs(data, "subAgents", ("agent", "displayName", "name")),
                "inst_agents": [
                    m.strip()
                    for m in AGENT_REF_RE.findall(inst_text)
                    if m.strip()
                ],
                "tool_refs": _refs(
                    data, "tools", ("tool", "displayName", "name")
                ),
                "toolset_refs": _refs(
                    data, "toolsets", ("toolset", "displayName", "name", "id")
                ),
                "inst_tools": [
                    m.strip()
                    for m in TOOL_REF_RE.findall(inst_text)
                    if m.strip()
                ],
                "raw": data,
            }
            alias[disp] = disp
            alias[agent_dir.name] = disp
            alias[aj_path.stem] = disp
            if aid:
                alias[aid] = disp

    active: list[str] = []
    visited: set[str] = set()
    start = alias.get(root_agent_name)
    if start:
        queue: deque[str] = deque([start])
        while queue:
            cur = queue.popleft()
            if cur in visited or cur not in agents_by_key:
                continue
            visited.add(cur)
            active.append(cur)
            info = agents_by_key[cur]
            for nxt in info["child_refs"] + info["inst_agents"]:
                key = alias.get(nxt)
                if key and key not in visited:
                    queue.append(key)
    else:
        active = sorted(agents_by_key)
        visited = set(active)

    referenced_tools: set[str] = set()
    referenced_toolsets: set[str] = set()
    for name in active:
        info = agents_by_key[name]
        for ref in info["tool_refs"] + info["inst_tools"]:
            referenced_tools.add(ref)
            referenced_toolsets.add(ref)
        referenced_toolsets.update(info["toolset_refs"])

    tools_dir = root / "tools"
    if tools_dir.is_dir():
        for tjson in sorted(tools_dir.glob("*/*.json")):
            tdata = read_json(tjson)
            tool_aliases = {
                a
                for a in (
                    tjson.parent.name,
                    str(tdata.get("displayName") or "").strip(),
                    str(tdata.get("name") or "").strip(),
                )
                if a
            }
            if active and not (tool_aliases & referenced_tools):
                continue
            ts_tool = tdata.get("toolsetTool")
            if isinstance(ts_tool, dict):
                ts_ref = str(ts_tool.get("toolset") or "").strip()
                if ts_ref:
                    referenced_toolsets.add(ts_ref)
                    if "/toolsets/" in ts_ref:
                        referenced_toolsets.add(
                            ts_ref.split("/toolsets/")[-1].split("/")[0]
                        )

    return {
        "root_agent": root_agent_name,
        "active_agents": active,
        "visited": visited,
        "orphan_agents": sorted(set(agents_by_key) - visited),
        "agents_by_key": agents_by_key,
        "alias_to_key": alias,
        "referenced_tools": referenced_tools,
        "referenced_toolsets": referenced_toolsets,
    }


def _combined_python_tools(root: Path, referenced_tools: set[str]) -> str:
    tools_dir = root / "tools"
    if not tools_dir.is_dir():
        return ""
    blobs = [
        read_text(py_file) or ""
        for py_file in sorted(tools_dir.glob("*/python_function/*.py"))
        if not py_file.is_symlink()
        and (
            not referenced_tools
            or py_file.parent.parent.name in referenced_tools
        )
    ]
    return "\n".join(blobs)


def _toolset_kind(data: dict[str, Any]) -> str:
    if "mcpToolset" in data:
        return "mcpToolset"
    if "openApiToolset" in data:
        return "openApiToolset"
    return "other"


def _is_toolset_bound(
    aliases: set[str],
    disp: str,
    dir_name: str,
    kind: str,
    refs: set[str],
    combined_py: str,
    env_toolsets: dict[str, Any],
) -> bool:
    if any(
        ref in aliases
        or any(
            ref.startswith((f"{a}_", f"{a}/", f"{a}:", f"{a}."))
            for a in aliases
            if a
        )
        for ref in refs
    ):
        return True
    if combined_py and any(
        f"{a}_" in combined_py for a in (disp, dir_name) if a
    ):
        return True
    return kind == "openApiToolset" and (
        disp in env_toolsets or dir_name in env_toolsets
    )


def prune_orphan_toolsets(
    root: Path, graph: dict[str, Any], env_data: dict[str, Any]
) -> tuple[list[str], list[dict[str, Any]]]:
    """Remove toolsets that no active agent or Python tool uses on pull."""
    toolsets_dir = root / "toolsets"
    active: list[str] = []
    pruned: list[dict[str, Any]] = []
    if not toolsets_dir.is_dir():
        return active, pruned
    refs = graph["referenced_toolsets"] | graph["referenced_tools"]
    env_toolsets = (
        env_data.get("toolsets")
        if isinstance(env_data.get("toolsets"), dict)
        else {}
    )
    combined_py = _combined_python_tools(root, graph["referenced_tools"])

    for ts_dir in sorted(toolsets_dir.iterdir()):
        if not ts_dir.is_dir() or ts_dir.name.startswith("."):
            continue
        json_files = sorted(ts_dir.glob("*.json"))
        if not json_files:
            continue
        data = read_json(json_files[0])
        disp = str(data.get("displayName") or ts_dir.name).strip()
        ts_id = str(data.get("name") or "").strip()
        aliases = {a for a in (disp, ts_dir.name, ts_id) if a}
        kind = _toolset_kind(data)
        if _is_toolset_bound(
            aliases, disp, ts_dir.name, kind, refs, combined_py, env_toolsets
        ):
            active.append(disp)
            continue
        pruned.append(
            {
                "name": disp,
                "dir_name": ts_dir.name,
                "kind": kind,
                "path": str(json_files[0].relative_to(root)),
                "reason": "no active agent or Python tool uses it",
            }
        )
        shutil.rmtree(ts_dir)

    if pruned and env_toolsets:
        changed = False
        for item in pruned:
            for key in (item["name"], item["dir_name"]):
                if key in env_toolsets:
                    del env_toolsets[key]
                    changed = True
        if changed and (root / "environment.json").is_file():
            write_json(root / "environment.json", env_data)
    return sorted(active), pruned


def prune_staged_orphan_toolsets(
    staging_path: Path,
    graph: dict[str, Any],
    env_data: dict[str, Any],
    manifest_data: dict[str, Any],
) -> list[str]:
    """Prune unattached orphan toolsets from `staging_path/toolsets/` and `env_data`."""
    toolsets_dir = staging_path / "toolsets"
    pruned: list[str] = []
    env_toolsets = (
        env_data.get("toolsets")
        if isinstance(env_data.get("toolsets"), dict)
        else None
    )
    manifest_orphans = set(manifest_data.get("pruned_orphans", []) or [])
    if isinstance(env_toolsets, dict):
        for mo in manifest_orphans:
            env_toolsets.pop(mo, None)
    if not toolsets_dir.is_dir():
        return pruned

    refs = graph["referenced_toolsets"] | graph["referenced_tools"]
    manifest_active = set(manifest_data.get("active_toolsets", []) or [])
    combined_py = _combined_python_tools(
        staging_path, graph["referenced_tools"]
    )
    env_map = env_toolsets if isinstance(env_toolsets, dict) else {}

    for ts_dir in sorted(toolsets_dir.iterdir()):
        if not ts_dir.is_dir() or ts_dir.name.startswith("."):
            continue
        json_files = sorted(ts_dir.glob("*.json"))
        ts_data = read_json(json_files[0]) if json_files else {}
        disp = str(ts_data.get("displayName") or ts_dir.name).strip()
        ts_id = str(ts_data.get("name") or "").strip()
        aliases = {a for a in (disp, ts_dir.name, ts_id) if a}
        kind = _toolset_kind(ts_data)
        attached = not (aliases & manifest_orphans) and (
            bool(aliases & manifest_active)
            or _is_toolset_bound(
                aliases, disp, ts_dir.name, kind, refs, combined_py, env_map
            )
        )
        if not attached:
            shutil.rmtree(ts_dir)
            pruned.append(disp)
            if isinstance(env_toolsets, dict):
                for al in aliases:
                    env_toolsets.pop(al, None)

    if isinstance(env_toolsets, dict) and (refs | manifest_active):
        for k, v in list(env_toolsets.items()):
            if not isinstance(v, dict) or "openApiToolset" in v:
                continue
            if k not in manifest_active and not _is_toolset_bound(
                {k}, k, k, "other", refs, combined_py, {}
            ):
                env_toolsets.pop(k, None)
                if k not in pruned:
                    pruned.append(k)
    return pruned
