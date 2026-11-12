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

"""Pre-push invariant and live-voice readiness gates for `cxas push --passport`."""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from typing import Any

import yaml

from cxas_scrapi.utils.passport.agent_graph import extract_agent_graph
from cxas_scrapi.utils.passport.files import read_json, safe_bundle_file
from cxas_scrapi.utils.passport.gates_voice import check_gate5_voice_safety

__all__ = [
    "gate6_report",
    "verify_passport_invariants",
]

logger = logging.getLogger(__name__)

PLATFORM_BUILTIN_TOOLS = {
    "end_session",
    "transfer_to_agent",
    "exit_loop",
}

CALLBACK_FIELDS = (
    "beforeAgentCallbacks",
    "afterAgentCallbacks",
    "beforeModelCallbacks",
    "afterModelCallbacks",
    "beforeToolCallbacks",
    "afterToolCallbacks",
)


def _check_gate3_bindings(
    staging_path: Path,
    agents_by_key: dict[str, dict[str, Any]],
    alias_to_key: dict[str, str],
) -> list[str]:
    """Run Gate 3: {@AGENT: ...} and {@TOOL: ...} binding parity and disk existence."""
    errors: list[str] = []
    known_tools: set[str] = set(PLATFORM_BUILTIN_TOOLS)
    tools_dir = staging_path / "tools"
    if tools_dir.is_dir():
        for tool_dir in sorted(tools_dir.iterdir()):
            if not tool_dir.is_dir() or tool_dir.name.startswith("."):
                continue
            known_tools.add(tool_dir.name)
            for tj in sorted(tool_dir.glob("*.json")):
                try:
                    tdata = json.loads(tj.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, ValueError) as exc:
                    errors.append(
                        f"Invalid tool JSON '{tj.relative_to(staging_path)}': {exc}"
                    )
                    continue
                if not isinstance(tdata, dict):
                    continue
                for k in ("displayName", "name"):
                    val = tdata.get(k)
                    if isinstance(val, str) and val.strip():
                        known_tools.add(val.strip())
                py_fn = tdata.get("pythonFunction")
                if isinstance(py_fn, dict):
                    fn_name = py_fn.get("name")
                    if isinstance(fn_name, str) and fn_name.strip():
                        known_tools.add(fn_name.strip())
                    py_rel = py_fn.get("pythonCode")
                    if (
                        isinstance(py_rel, str)
                        and py_rel.strip()
                        and safe_bundle_file(staging_path, py_rel.strip())
                        is None
                    ):
                        errors.append(
                            f"Tool '{tool_dir.name}' references missing pythonCode '{py_rel}'"
                        )

    known_toolsets: set[str] = set()
    toolset_prefixes: set[str] = set()
    toolsets_dir = staging_path / "toolsets"
    if toolsets_dir.is_dir():
        for ts_dir in sorted(toolsets_dir.iterdir()):
            if not ts_dir.is_dir() or ts_dir.name.startswith("."):
                continue
            known_toolsets.add(ts_dir.name)
            toolset_prefixes.add(f"{ts_dir.name}_")
            for tsj in sorted(ts_dir.glob("*.json")):
                tdata = read_json(tsj)
                for k in ("displayName", "name"):
                    val = tdata.get(k)
                    if isinstance(val, str) and val.strip():
                        known_toolsets.add(val.strip())
                        toolset_prefixes.add(f"{val.strip()}_")
                openapi_cfg = tdata.get("openApiToolset")
                if isinstance(openapi_cfg, dict):
                    schema_rel = openapi_cfg.get("openApiSchema")
                    schema_path = (
                        safe_bundle_file(staging_path, schema_rel)
                        if isinstance(schema_rel, str) and schema_rel
                        else safe_bundle_file(
                            staging_path,
                            f"toolsets/{ts_dir.name}/open_api_toolset/open_api_schema.yaml",
                        )
                    )
                    if schema_path is not None:
                        try:
                            schema_doc = yaml.safe_load(
                                schema_path.read_text(encoding="utf-8")
                            )
                            if isinstance(schema_doc, dict):
                                for methods in (
                                    schema_doc.get("paths", {}) or {}
                                ).values():
                                    if isinstance(methods, dict):
                                        for op in methods.values():
                                            if isinstance(op, dict):
                                                op_id = op.get("operationId")
                                                if op_id:
                                                    known_tools.add(
                                                        f"{ts_dir.name}_{op_id}"
                                                    )
                        except (
                            OSError,
                            UnicodeDecodeError,
                            yaml.YAMLError,
                        ) as exc:
                            logger.debug(
                                "could not parse OpenAPI schema %s: %s",
                                schema_path,
                                exc,
                            )

    for disp, ainfo in sorted(agents_by_key.items()):
        adata = ainfo["raw"]
        inst_rel = adata.get("instruction")
        if (
            isinstance(inst_rel, str)
            and inst_rel.strip()
            and ainfo["inst_path"] is None
        ):
            errors.append(
                f"Agent '{disp}' references missing instruction file '{inst_rel}'"
            )

        declared_children = set(ainfo["child_refs"])
        declared_children_canonical = {
            alias_to_key.get(c, c) for c in declared_children
        }
        for c in declared_children:
            if c not in alias_to_key:
                errors.append(
                    f"Agent '{disp}' declares non-existent childAgent '{c}'"
                )

        for ref_ag in ainfo["inst_agents"]:
            ref_canonical = alias_to_key.get(ref_ag, ref_ag)
            if (
                ref_ag not in declared_children
                and ref_canonical not in declared_children_canonical
            ):
                errors.append(
                    f"Agent '{disp}' instruction references {{@AGENT: {ref_ag}}} not declared in childAgents {sorted(declared_children)}"
                )
            if ref_ag not in alias_to_key:
                errors.append(
                    f"Agent '{disp}' instruction references non-existent agent {{@AGENT: {ref_ag}}}"
                )

        declared_tools = set(ainfo["tool_refs"])
        declared_toolsets = set(ainfo["toolset_refs"])

        for ts_ref in declared_toolsets:
            ts_short = (
                ts_ref.split("/toolsets/")[-1].split("/")[0]
                if "/toolsets/" in ts_ref
                else ts_ref
            )
            if ts_ref not in known_toolsets and ts_short not in known_toolsets:
                errors.append(
                    f"Agent '{disp}' declares non-existent toolset '{ts_ref}'"
                )

        agent_ts_prefixes = {f"{ts}_" for ts in declared_toolsets} | {
            f"{ts.split('/toolsets/')[-1].split('/')[0]}_"
            for ts in declared_toolsets
            if "/toolsets/" in ts
        }

        for t_ref in declared_tools:
            in_known_toolset = any(
                t_ref.startswith(pfx)
                for pfx in (agent_ts_prefixes | toolset_prefixes)
            )
            if t_ref not in known_tools and not in_known_toolset:
                errors.append(
                    f"Agent '{disp}' declares unknown tool '{t_ref}' not found in tools/ or toolsets/"
                )

        for inst_tool in ainfo["inst_tools"]:
            covered_by_toolset = inst_tool in declared_toolsets or any(
                inst_tool.startswith(pfx) for pfx in agent_ts_prefixes
            )
            if inst_tool not in declared_tools and not covered_by_toolset:
                errors.append(
                    f"Agent '{disp}' instruction references {{@TOOL: {inst_tool}}} not declared in agent tools {sorted(declared_tools)}"
                )
            in_disk_toolset = inst_tool in known_toolsets or any(
                inst_tool.startswith(pfx) for pfx in toolset_prefixes
            )
            if inst_tool not in known_tools and not in_disk_toolset:
                errors.append(
                    f"Agent '{disp}' instruction references {{@TOOL: {inst_tool}}} which does not exist on disk"
                )
    return errors


def verify_passport_invariants(
    staging_dir: str | Path,
    strict_gates: bool = False,
) -> dict[str, Any]:
    """Run all 5 Pre-Push Invariant & Live-Voice Readiness Gates on `staging_dir`."""
    staging_path = Path(staging_dir).resolve()

    gate_1_errors: list[str] = []
    gate_2_warnings: list[str] = []
    gate_4_errors: list[str] = []

    app_json_path = staging_path / "app.json"
    app_data: dict[str, Any] = {}
    if not app_json_path.is_file():
        gate_1_errors.append(f"Missing app.json in {staging_path}")
    else:
        try:
            loaded = json.loads(app_json_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                gate_1_errors.append("app.json must be a JSON object")
            else:
                app_data = loaded
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            gate_1_errors.append(f"Invalid JSON in app.json: {exc}")

    graph = extract_agent_graph(staging_path, app_data or None)
    agents_by_key = graph["agents_by_key"]
    alias_to_key = graph["alias_to_key"]
    root_agent_name = graph["root_agent"]

    if app_json_path.is_file() and not gate_1_errors:
        if not root_agent_name:
            gate_1_errors.append(
                "Missing or empty 'rootAgent' field in app.json"
            )
        elif root_agent_name not in alias_to_key:
            gate_1_errors.append(
                f"rootAgent '{root_agent_name}' declared in app.json not found in agents/"
            )

    visited = graph["visited"]
    orphan_agents = sorted(set(agents_by_key.keys()) - visited)
    if orphan_agents:
        gate_2_warnings.append(
            f"Disconnected orphan agents unreachable from rootAgent '{root_agent_name}': {orphan_agents}"
        )

    parent_map: dict[str, list[str]] = {k: [] for k in agents_by_key}
    for parent_key, ainfo in agents_by_key.items():
        for child_raw in ainfo["child_refs"]:
            child_key = alias_to_key.get(child_raw)
            if child_key and child_key in parent_map:
                parent_map[child_key].append(parent_key)
    for ag_key, parents in sorted(parent_map.items()):
        if len(parents) > 1:
            gate_2_warnings.append(
                f"Agent '{ag_key}' has multiple parents {sorted(parents)} (violates single-parent tree)"
            )

    gate_3_errors = _check_gate3_bindings(
        staging_path, agents_by_key, alias_to_key
    )

    py_files_to_check: set[Path] = set()
    for sub_dir in (staging_path / "tools", staging_path / "agents"):
        if sub_dir.is_dir():
            py_files_to_check.update(
                p
                for p in sub_dir.rglob("*.py")
                if p.is_file() and not p.is_symlink()
            )

    for disp, ainfo in sorted(agents_by_key.items()):
        adata = ainfo["raw"]
        agent_dir = ainfo["json_path"].parent
        for cb_field in CALLBACK_FIELDS:
            for cb in adata.get(cb_field, []) or []:
                if not isinstance(cb, dict):
                    continue
                cb_rel = cb.get("pythonCode")
                if isinstance(cb_rel, str) and cb_rel.strip():
                    resolved_cb = safe_bundle_file(
                        staging_path, cb_rel.strip()
                    ) or safe_bundle_file(
                        staging_path, cb_rel.strip(), base=agent_dir
                    )
                    if resolved_cb is not None:
                        py_files_to_check.add(resolved_cb)
                    else:
                        gate_4_errors.append(
                            f"Agent '{disp}' ({cb_field}) references missing callback file '{cb_rel}'"
                        )

    parsed_asts: dict[Path, ast.AST] = {}
    for py_path in sorted(py_files_to_check):
        rel_py = str(py_path.relative_to(staging_path))
        try:
            src = py_path.read_text(encoding="utf-8")
            parsed_asts[py_path] = ast.parse(src, filename=rel_py)
        except SyntaxError as exc:
            gate_4_errors.append(
                f"Python syntax error in '{rel_py}' (line {exc.lineno}): {exc.msg}"
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            gate_4_errors.append(
                f"Failed to parse Python file '{rel_py}': {exc}"
            )

    gate_5_warnings = check_gate5_voice_safety(
        staging_path, app_data, agents_by_key, py_files_to_check, parsed_asts
    )

    g1_dict = {
        "name": "root_agent_exists",
        "fatal": True,
        "passed": len(gate_1_errors) == 0,
        "errors": gate_1_errors,
        "warnings": [],
        "issues": list(gate_1_errors),
    }
    g2_dict = {
        "name": "connected_agent_graph",
        "fatal": False,
        "passed": len(gate_2_warnings) == 0,
        "errors": [],
        "warnings": gate_2_warnings,
        "issues": list(gate_2_warnings),
    }
    g3_dict = {
        "name": "instruction_binding_parity",
        "fatal": True,
        "passed": len(gate_3_errors) == 0,
        "errors": gate_3_errors,
        "warnings": [],
        "issues": list(gate_3_errors),
    }
    g4_dict = {
        "name": "python_ast_syntax",
        "fatal": True,
        "passed": len(gate_4_errors) == 0,
        "errors": gate_4_errors,
        "warnings": [],
        "issues": list(gate_4_errors),
    }
    g5_dict = {
        "name": "live_voice_and_anti_overfit",
        "fatal": False,
        "passed": len(gate_5_warnings) == 0,
        "errors": [],
        "warnings": gate_5_warnings,
        "issues": list(gate_5_warnings),
    }

    primary_gates = [
        ("Gate 1", "gate_1", g1_dict),
        ("Gate 2", "gate_2", g2_dict),
        ("Gate 3", "gate_3", g3_dict),
        ("Gate 4", "gate_4", g4_dict),
        ("Gate 5", "gate_5", g5_dict),
    ]
    gates = {
        "gate_1": g1_dict,
        "gate_2": g2_dict,
        "gate_3": g3_dict,
        "gate_4": g4_dict,
        "gate_5": g5_dict,
        "gate1_app_and_root": g1_dict,
        "gate2_agent_graph": g2_dict,
        "gate3_binding_parity": g3_dict,
        "gate4_python_ast": g4_dict,
        "gate5_live_voice_safety": g5_dict,
    }

    fatal_errors = gate_1_errors + gate_3_errors + gate_4_errors
    all_warnings = gate_2_warnings + gate_5_warnings
    fatal_passed = len(fatal_errors) == 0
    gates_passed = fatal_passed and len(all_warnings) == 0

    lines = [
        f"=== CXAS Passport Pre-Push Invariant Report ({staging_path}) ==="
    ]
    for g_label, g_key, g_info in primary_gates:
        status_str = (
            "PASS"
            if g_info["passed"]
            else ("FAIL" if g_info["fatal"] else "WARN")
        )
        lines.append(f"  [{status_str}] {g_label} / {g_key} ({g_info['name']})")
        for err in g_info["errors"]:
            lines.append(f"    - ERROR: {err}")
        for warn in g_info["warnings"]:
            lines.append(f"    - WARN:  {warn}")
    formatted_report = "\n".join(lines)

    if strict_gates and not fatal_passed:
        raise ValueError(formatted_report)

    return {
        "gates_passed": gates_passed,
        "fatal_passed": fatal_passed,
        "gates": gates,
        "errors": fatal_errors,
        "warnings": all_warnings,
        "formatted_report": formatted_report,
    }


def gate6_report(
    base: dict[str, Any],
    unresolved: list[tuple[str, int, str]],
    placeholders: dict[str, Any],
    strict_gates: bool,
) -> dict[str, Any]:
    """Merge Gate 6 (placeholders resolved) into a `verify_passport_invariants` report."""
    errors = []
    for rel, line, name in unresolved:
        how = str((placeholders.get(name) or {}).get("how_set") or "").replace(
            "`", ""
        )
        errors.append(
            f"{rel}:{line} still holds ${{{name}}}"
            + (f" (set it with: {how})" if how else "")
        )
    gate = {
        "name": "placeholders_resolved",
        "fatal": True,
        "passed": not errors,
        "errors": errors,
        "warnings": [],
        "issues": list(errors),
    }
    gates = dict(base["gates"])
    gates["gate_6"] = gate
    gates["gate6_placeholders_resolved"] = gate
    fatal_errors = list(base["errors"]) + errors
    fatal_passed = not fatal_errors
    lines = [
        base["formatted_report"],
        f"  [{'PASS' if gate['passed'] else 'FAIL'}] Gate 6 / gate_6 (placeholders_resolved)",
    ]
    lines += [f"    - ERROR: {err}" for err in errors]
    report = {
        **base,
        "gates": gates,
        "errors": fatal_errors,
        "fatal_passed": fatal_passed,
        "gates_passed": fatal_passed and not base["warnings"],
        "formatted_report": "\n".join(lines),
    }
    if strict_gates and not fatal_passed:
        raise ValueError(report["formatted_report"])
    return report
