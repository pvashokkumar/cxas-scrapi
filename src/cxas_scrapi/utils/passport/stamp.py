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

"""Placeholder stamping and staging normalization helpers for `cxas push --passport`."""

from __future__ import annotations

import ast
import json
import re
import shutil
import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.files import read_json, write_json
from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PLACEHOLDERS_GUIDE_NAME,
)
from cxas_scrapi.utils.passport.verify import TOKEN_RE, iter_text_files

if TYPE_CHECKING:
    from pathlib import Path

MOH_ASSIGN_RE = re.compile(
    r"^(\s*(?:_MOH_AUDIO_URI|MOH_AUDIO_URI)\s*=\s*)([\"'])(.*?)(\2)",
    re.MULTILINE,
)

NON_CES_ROOT_ITEMS = {
    PASSPORT_DIR_NAME,
    PLACEHOLDERS_GUIDE_NAME,
    "scripts",
    ".git",
    ".gitignore",
    "__pycache__",
}


def is_placeholder(val: Any) -> bool:
    if not isinstance(val, str) or not val.strip():
        return True
    s = val.strip()
    return (
        s == "$env_var"
        or s.startswith("${")
        or (s.startswith("<") and s.endswith(">"))
    )


def normalize_toolbox_url(url: str | None) -> str | None:
    if not url or not isinstance(url, str) or is_placeholder(url):
        return None
    cleaned = url.strip()
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.path in ("", "/"):
        return cleaned.rstrip("/") + "/mcp"
    return cleaned


def clean_non_ces_items(staging_path: Path) -> list[str]:
    """Remove non-CES directories and files from staging_dir."""
    removed: list[str] = []
    if not staging_path.is_dir():
        return removed
    for item_name in sorted(NON_CES_ROOT_ITEMS):
        target = staging_path / item_name
        if target.is_dir():
            shutil.rmtree(target)
            removed.append(item_name)
        elif target.is_file() or target.is_symlink():
            target.unlink()
            removed.append(item_name)
    return removed


def normalize_enums_recursive(obj: Any) -> tuple[Any, int]:
    """Recursively normalize deprecated proto enums: DISALLOW -> FAIL."""
    if isinstance(obj, dict):
        count = 0
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k == "extraToolCallBehavior" and v == "DISALLOW":
                out[k] = "FAIL"
                count += 1
            else:
                new_v, c = normalize_enums_recursive(v)
                out[k] = new_v
                count += c
        return out, count
    if isinstance(obj, list):
        total = 0
        out_list: list[Any] = []
        for item in obj:
            new_item, c = normalize_enums_recursive(item)
            out_list.append(new_item)
            total += c
        return out_list, total
    return obj, 0


def stamp_tokens(
    root: Path, values: dict[str, str], names: set[str]
) -> set[str]:
    """Replace `${NAME}` for every NAME in `names` that has a value. Returns changed files."""
    stamped: set[str] = set()
    for path, text in iter_text_files(root):

        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            return (
                values[name]
                if name in names and name in values
                else match.group(0)
            )

        new = TOKEN_RE.sub(_sub, text)
        if new == text:
            continue
        rel = str(path.relative_to(root))
        if path.suffix == ".json":
            try:
                json.loads(new)
            except ValueError as exc:
                raise ValueError(
                    f"{rel}: a placeholder value breaks the JSON ({exc}); check the --set values"
                ) from exc
        elif path.suffix == ".py":
            try:
                ast.parse(new, filename=rel)
            except SyntaxError as exc:
                raise ValueError(
                    f"{rel}: a placeholder value breaks the Python code ({exc.msg}); check the --set values"
                ) from exc
        path.write_text(new, encoding="utf-8")
        stamped.add(rel)
    return stamped


def unresolved_tokens(
    root: Path, names: set[str]
) -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for path, text in iter_text_files(root):
        rel = str(path.relative_to(root))
        for idx, line in enumerate(text.splitlines(), start=1):
            for match in TOKEN_RE.finditer(line):
                if match.group(1) in names:
                    found.append((rel, idx, match.group(1)))
    return found


def set_mcp_server_address(
    root: Path, env_data: dict[str, Any], url: str
) -> tuple[set[str], int]:
    """Point every MCP toolset at `url` (the `--toolbox-url` override)."""
    stamped: set[str] = set()
    count = 0
    toolsets_dir = root / "toolsets"
    if toolsets_dir.is_dir():
        for ts_json in sorted(toolsets_dir.glob("*/*.json")):
            data = read_json(ts_json)
            if isinstance(data.get("mcpToolset"), dict):
                count += 1
                if data["mcpToolset"].get("serverAddress") != url:
                    data["mcpToolset"]["serverAddress"] = url
                    write_json(ts_json, data)
                    stamped.add(str(ts_json.relative_to(root)))
    env_toolsets = (
        env_data.get("toolsets")
        if isinstance(env_data.get("toolsets"), dict)
        else {}
    )
    for entry in env_toolsets.values():
        if isinstance(entry, dict) and isinstance(
            entry.get("mcpToolset"), dict
        ):
            entry["mcpToolset"]["serverAddress"] = url
            stamped.add("environment.json")
    return stamped, count


def set_logging_buckets(data: dict[str, Any], bucket: str) -> bool:
    changed = False
    settings = data.get("loggingSettings")
    if not isinstance(settings, dict):
        return False
    for key in ("evaluationAudioRecordingConfig", "audioRecordingConfig"):
        cfg = settings.get(key)
        if isinstance(cfg, dict) and cfg.get("gcsBucket") not in (
            None,
            "$env_var",
            bucket,
        ):
            cfg["gcsBucket"] = bucket
            changed = True
    return changed


def stamp_moh_uri(staging_path: Path, target_moh_uri: str) -> set[str]:
    """Safely rewrite `_MOH_AUDIO_URI` / `MOH_AUDIO_URI` string literals in callback Python files."""
    stamped: set[str] = set()
    agents_dir = staging_path / "agents"
    if not agents_dir.is_dir():
        return stamped
    literal = json.dumps(target_moh_uri)
    for cb_file in sorted(agents_dir.glob("*/*_callbacks/*/*.py")):
        src = cb_file.read_text(encoding="utf-8")
        new, count = MOH_ASSIGN_RE.subn(
            lambda m: f"{m.group(1)}{literal}", src, count=1
        )
        if count and new != src:
            rel = str(cb_file.relative_to(staging_path))
            ast.parse(new, filename=rel)
            cb_file.write_text(new, encoding="utf-8")
            stamped.add(rel)
    return stamped
