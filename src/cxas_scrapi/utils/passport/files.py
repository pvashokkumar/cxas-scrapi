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

"""File helpers for the agent export folder that a passport pull rewrites."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PLACEHOLDERS_GUIDE_NAME,
)

# Files of an export that the agent runs with: only these are scanned for the
# Google Cloud resources the agent depends on (evaluations, examples and docs
# are scrubbed but never create resources).
RUNTIME_ROOTS = (
    "app.json",
    "app.yaml",
    "environment.json",
    "global_instruction.txt",
    "agents",
    "tools",
    "toolsets",
    "guardrails",
    "shared",
)
SKIP_DIRS = {".git", "__pycache__", "node_modules"}


def read_json(path: Path) -> dict[str, Any]:
    """The JSON object in `path`, or {} when it is missing or not an object."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_text(path: Path) -> str | None:
    """UTF-8 text of `path`, or None for binary or unreadable files."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
    return None if "\x00" in text else text


def resolve_root(app_root: str | Path) -> Path:
    """The folder that holds app.json (or agents/), possibly one level down."""
    root = Path(app_root).resolve()
    if (root / "app.json").is_file() or (root / "agents").is_dir():
        return root
    subdirs = [
        d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")
    ]
    if len(subdirs) == 1 and (
        (subdirs[0] / "app.json").is_file() or (subdirs[0] / "agents").is_dir()
    ):
        return subdirs[0]
    return root


def bundle_files(root: Path) -> list[Path]:
    """Files of the agent export (passport output excluded), sorted."""
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if (
            path.is_symlink()
            or not path.is_file()
            or any(p in SKIP_DIRS for p in rel_parts)
        ):
            continue
        if rel_parts[0] == PASSPORT_DIR_NAME or rel_parts == (
            PLACEHOLDERS_GUIDE_NAME,
        ):
            continue
        out.append(path)
    return out


def safe_rel_subpath(rel: str) -> str | None:
    """Normalized POSIX relative subpath inside a folder, or None if unsafe."""
    if not rel or "\x00" in rel or "\\" in rel or rel.startswith("/"):
        return None
    pure = PurePosixPath(rel)
    if pure.is_absolute() or not pure.parts:
        return None
    if any(part in ("", ".", "..") for part in pure.parts):
        return None
    return pure.as_posix()


def safe_bundle_file(
    root: Path, rel: str, *, base: Path | None = None
) -> Path | None:
    """File inside `root` named by `rel`, or None if missing, symlink, or outside `root`."""
    if not rel or "\x00" in rel or "\\" in rel or Path(rel).is_absolute():
        return None
    anchor = base if base is not None else root
    cand = anchor / rel
    if cand.is_symlink():
        return None
    try:
        resolved_root = root.resolve()
        resolved = cand.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        return None
    return root / resolved.relative_to(resolved_root)


def is_runtime_file(rel: str) -> bool:
    return rel.split("/", 1)[0] in RUNTIME_ROOTS


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def usage_label(rel: str, line: int | None = None) -> str:
    """Readable "who uses it" label for a file (and line) of the agent."""
    parts = rel.split("/")
    where = f"`{rel}`" + (f" line {line}" if line else "")
    if parts[0] == "toolsets" and len(parts) > 1:
        return f"toolset `{parts[1]}` ({where})"
    if parts[0] == "tools" and len(parts) > 1:
        kind = "Python tool" if "python_function" in parts else "tool"
        return f"{kind} `{parts[1]}` ({where})"
    if (
        parts[0] == "agents"
        and len(parts) > 2
        and parts[2].endswith("_callbacks")
    ):
        return f"callback of agent `{parts[1]}` ({where})"
    if parts[0] == "agents" and len(parts) > 1:
        return f"agent `{parts[1]}` ({where})"
    if parts[0] == "guardrails" and len(parts) > 1:
        return f"guardrail `{parts[1]}` ({where})"
    if rel == "app.json":
        return f"app settings ({where})"
    return where


def safe_folder(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
    return cleaned or "resource"


def bucket_folder(
    name: str, project_id: str | None, project_number: str | None
) -> str:
    """Folder name of a bucket without the project ID or number in it."""
    cleaned = name
    for raw in (project_id, project_number):
        if raw:
            cleaned = cleaned.replace(raw, "")
    cleaned = re.sub(r"[-_.]{2,}", "-", cleaned).strip("-_.")
    return safe_folder(cleaned or "bucket")
