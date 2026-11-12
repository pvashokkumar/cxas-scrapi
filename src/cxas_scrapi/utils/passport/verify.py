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

"""Post-upload CES read-back verification for `cxas push --passport`."""

from __future__ import annotations

import io
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from cxas_scrapi.utils.passport.files import read_json

TOKEN_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


def iter_text_files(root: Path) -> list[tuple[Path, str]]:
    """Read all UTF-8 text files below `root` in sorted order."""
    out: list[tuple[Path, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        out.append((path, text))
    return out


def _export_root(base: Path) -> Path:
    if (base / "app.json").is_file() or (base / "app.yaml").is_file():
        return base
    for child in sorted(base.iterdir()):
        if child.is_dir() and (
            (child / "app.json").is_file() or (child / "app.yaml").is_file()
        ):
            return child
    return base


def _agent_bindings(root: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    agents_dir = root / "agents"
    if not agents_dir.is_dir():
        return out
    for agent_dir in sorted(agents_dir.iterdir()):
        json_files = (
            sorted(agent_dir.glob("*.json")) if agent_dir.is_dir() else []
        )
        if not json_files:
            continue
        data = read_json(json_files[0])
        name = str(data.get("displayName") or agent_dir.name)
        toolsets: dict[str, list[str]] = {}
        for item in data.get("toolsets") or []:
            if isinstance(item, dict) and item.get("toolset"):
                ref = str(item["toolset"]).split("/toolsets/")[-1].split("/")[0]
                toolsets[ref] = sorted(
                    str(t) for t in item.get("toolIds") or []
                )
            elif isinstance(item, str):
                toolsets[item] = []
        tools = sorted(
            str(t) for t in data.get("tools") or [] if isinstance(t, str)
        )
        out[name] = {"toolsets": toolsets, "tools": tools}
    return out


def _named_dirs(root: Path, folder: str) -> set[str]:
    base = root / folder
    names: set[str] = set()
    if not base.is_dir():
        return names
    for child in base.iterdir():
        json_files = sorted(child.glob("*.json")) if child.is_dir() else []
        if json_files:
            names.add(
                str(read_json(json_files[0]).get("displayName") or child.name)
            )
    return names


def compare_pushed_app(staged_root: Path, pushed_root: Path) -> list[str]:
    """What the uploaded files declare but the app read back from CES lacks."""
    problems: list[str] = []
    staged_app = read_json(staged_root / "app.json")
    pushed_app = read_json(pushed_root / "app.json")
    staged_model = (staged_app.get("modelSettings") or {}).get("model")
    pushed_model = (pushed_app.get("modelSettings") or {}).get("model")
    if staged_model and staged_model != pushed_model:
        problems.append(
            f"model: the upload declares {staged_model!r} but the app has "
            f"{repr(pushed_model) if pushed_model else 'no model (the platform default)'}; "
            "CES drops a model that is not available in the app's location"
        )
    for folder, label in (("toolsets", "toolset"), ("tools", "tool")):
        missing = sorted(
            _named_dirs(staged_root, folder) - _named_dirs(pushed_root, folder)
        )
        for name in missing:
            hint = (
                " (CES drops a toolset whose URL or authentication it cannot use)"
                if label == "toolset"
                else ""
            )
            problems.append(f"{label} {name!r} is missing from the app{hint}")
    staged_agents = _agent_bindings(staged_root)
    pushed_agents = _agent_bindings(pushed_root)
    for agent, binding in sorted(staged_agents.items()):
        pushed = pushed_agents.get(agent)
        if pushed is None:
            problems.append(f"agent {agent!r} is missing from the app")
            continue
        for toolset, tool_ids in sorted(binding["toolsets"].items()):
            if toolset not in pushed["toolsets"]:
                problems.append(
                    f"agent {agent!r} lost its binding to toolset {toolset!r}"
                )
            elif sorted(pushed["toolsets"][toolset]) != tool_ids:
                problems.append(
                    f"agent {agent!r}: toolset {toolset!r} tools {pushed['toolsets'][toolset]} != uploaded {tool_ids}"
                )
        lost_tools = sorted(set(binding["tools"]) - set(pushed["tools"]))
        if lost_tools:
            problems.append(f"agent {agent!r} lost tools {lost_tools}")
    for path, text in iter_text_files(pushed_root):
        tokens = sorted(
            {
                m.group(1)
                for m in TOKEN_RE.finditer(text)
                if m.group(1) in ("GCP_PROJECT", "GCP_PROJECT_NUMBER")
            }
        )
        if tokens:
            problems.append(
                f"{path.relative_to(pushed_root)} still holds {', '.join('${' + t + '}' for t in tokens)}"
            )
    return problems


def verify_pushed_app(
    apps_client: Any, app_name: str | None, staging_dir: str | Path
) -> dict[str, Any]:
    """Export the app after the upload and compare it with what was uploaded.

    Returns {"checked": bool, "ok": bool, "problems": [...], "warnings": [...]}.
    `checked` is False when the app could not be read back (a warning, not a
    failure).
    """
    report: dict[str, Any] = {
        "checked": False,
        "ok": True,
        "problems": [],
        "warnings": [],
    }
    if not app_name or apps_client is None:
        report["warnings"].append("no app to read back")
        return report
    try:
        lro = apps_client.export_app(app_name=app_name)
        response = lro.result() if hasattr(lro, "result") else lro
        content = getattr(response, "app_content", None)
        if not isinstance(content, (bytes, bytearray)) or not content:
            raise ValueError("the export returned no content")
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(io.BytesIO(bytes(content))) as zf:
                zf.extractall(tmp)
            report["problems"] = compare_pushed_app(
                Path(staging_dir), _export_root(Path(tmp))
            )
        report["checked"] = True
    except Exception as exc:
        report["warnings"].append(
            f"could not read the app back to check it: {exc}"
        )
        return report
    report["ok"] = not report["problems"]
    return report
