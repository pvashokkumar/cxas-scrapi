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

"""Gate 5: Anti-overfit and live-voice safety checks for `cxas push --passport`."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.files import read_json, safe_bundle_file

if TYPE_CHECKING:
    from pathlib import Path

HARDCODED_OTP_TOKEN_RE = re.compile(r"\b384920\b")
_INSTRUCTION_HARDCODED_OTP_RE_STR = (
    r"(?<!e\.g\.,\s)(?<!e\.g\.\s)\b(?:otp|passcode|verification\s+code)"
    r"\s*(?:is|=|==|:)\s*[\"']?\d{6}[\"']?"
)
INSTRUCTION_HARDCODED_OTP_RE = re.compile(
    _INSTRUCTION_HARDCODED_OTP_RE_STR,
    re.IGNORECASE,
)


def _get_schema_object_nesting_depth(
    schema: Any, current_object_depth: int = 0
) -> int:
    """Compute maximum nested object depth for FST output_schema check."""
    if not isinstance(schema, dict):
        return current_object_depth

    max_depth = current_object_depth
    props = schema.get("properties")
    if isinstance(props, dict):
        for prop_schema in props.values():
            if not isinstance(prop_schema, dict):
                continue
            ptype = str(prop_schema.get("type") or "").upper()
            has_sub_props = isinstance(prop_schema.get("properties"), dict)
            if ptype == "OBJECT" or has_sub_props:
                child_depth = _get_schema_object_nesting_depth(
                    prop_schema, current_object_depth + 1
                )
                max_depth = max(max_depth, child_depth)
            elif ptype == "ARRAY" and isinstance(
                prop_schema.get("items"), dict
            ):
                items_schema = prop_schema["items"]
                itype = str(items_schema.get("type") or "").upper()
                if itype == "OBJECT" or isinstance(
                    items_schema.get("properties"), dict
                ):
                    child_depth = _get_schema_object_nesting_depth(
                        items_schema, current_object_depth + 1
                    )
                    max_depth = max(max_depth, child_depth)
                else:
                    child_depth = _get_schema_object_nesting_depth(
                        items_schema, current_object_depth
                    )
                    max_depth = max(max_depth, child_depth)
    return max_depth


def check_gate5_voice_safety(
    staging_path: Path,
    app_data: dict[str, Any],
    agents_by_key: dict[str, dict[str, Any]],
    py_files_to_check: set[Path],
    parsed_asts: dict[Path, ast.AST],
) -> list[str]:
    """Run Gate 5 anti-overfit, FST schema depth, and callback safety checks."""
    warnings: list[str] = []
    tools_dir = staging_path / "tools"
    agents_dir = staging_path / "agents"

    text_files_for_otp: list[Path] = []
    if (staging_path / "global_instruction.txt").is_file():
        text_files_for_otp.append(staging_path / "global_instruction.txt")
    for ainfo in agents_by_key.values():
        if ainfo["inst_path"] and ainfo["inst_path"].is_file():
            text_files_for_otp.append(ainfo["inst_path"])
    text_files_for_otp.extend(sorted(py_files_to_check))

    for tf_path in text_files_for_otp:
        rel_tf = str(tf_path.relative_to(staging_path))
        try:
            content = tf_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if HARDCODED_OTP_TOKEN_RE.search(content):
            warnings.append(
                f"Hardcoded 6-digit OTP '384920' detected in '{rel_tf}' (anti-overfit violation)"
            )
        elif tf_path.suffix == ".txt" and INSTRUCTION_HARDCODED_OTP_RE.search(
            content
        ):
            warnings.append(
                f"Hardcoded 6-digit OTP literal detected in instruction '{rel_tf}' (anti-overfit violation)"
            )

    schema_candidates: list[tuple[str, Any]] = []
    for k in ("outputSchema", "output_schema"):
        if k in app_data:
            schema_candidates.append((f"app.json:{k}", app_data[k]))
    for _disp, ainfo in sorted(agents_by_key.items()):
        adata = ainfo["raw"]
        for k in ("outputSchema", "output_schema"):
            if k in adata:
                schema_candidates.append(
                    (f"agents/{ainfo['dir_name']}:{k}", adata[k])
                )
    if tools_dir.is_dir():
        for tj in sorted(tools_dir.glob("*/*.json")):
            tdata = read_json(tj)
            rel_tj = str(tj.relative_to(staging_path))
            for k in ("outputSchema", "output_schema", "responseSchema"):
                if k in tdata:
                    schema_candidates.append((f"{rel_tj}:{k}", tdata[k]))
            py_fn = tdata.get("pythonFunction")
            if isinstance(py_fn, dict):
                for k in ("outputSchema", "output_schema", "responseSchema"):
                    if k in py_fn:
                        schema_candidates.append(
                            (f"{rel_tj}:pythonFunction.{k}", py_fn[k])
                        )

    for label, schema_obj in schema_candidates:
        depth = _get_schema_object_nesting_depth(schema_obj, 0)
        if depth > 1:
            warnings.append(
                f"{label} has nested OBJECT depth {depth} > 1 (FST live-voice safety limit is <= 1)"
            )

    after_model_files: set[Path] = set()
    if agents_dir.is_dir():
        after_model_files.update(
            p
            for p in agents_dir.glob("*/after_model_callbacks/*/*.py")
            if p.is_file() and not p.is_symlink()
        )
    for ainfo in agents_by_key.values():
        agent_dir = ainfo["json_path"].parent
        for cb in ainfo["raw"].get("afterModelCallbacks", []) or []:
            if isinstance(cb, dict) and isinstance(cb.get("pythonCode"), str):
                cand = safe_bundle_file(
                    staging_path, cb["pythonCode"].strip()
                ) or safe_bundle_file(
                    staging_path, cb["pythonCode"].strip(), base=agent_dir
                )
                if cand is not None:
                    after_model_files.add(cand)

    for am_path in sorted(after_model_files):
        rel_am = str(am_path.relative_to(staging_path))
        tree = parsed_asts.get(am_path)
        if tree is None:
            continue
        has_try = any(isinstance(node, ast.Try) for node in ast.walk(tree))
        returns_dict_literal = any(
            isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
            for node in ast.walk(tree)
        )
        if returns_dict_literal:
            warnings.append(
                f"after_model_callback '{rel_am}' returns a raw dict literal instead of LlmResponse or None"
            )
        if not has_try:
            calls_or_attrs = [
                n
                for n in ast.walk(tree)
                if isinstance(
                    n, (ast.Call, ast.Attribute, ast.Subscript, ast.Dict)
                )
            ]
            if calls_or_attrs:
                warnings.append(
                    f"after_model_callback '{rel_am}' lacks try...except safety wrapper"
                )

    return warnings
