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

"""Placeholders in the agent files, and the scrubbed writer for passport files."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.files import read_text, safe_rel_subpath
from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PLACEHOLDER_NAME_RE,
    has_pinned_secret_version,
)

if TYPE_CHECKING:
    from pathlib import Path

    from cxas_scrapi.utils.passport.model import Scrubber


class Writer:
    """Writes passport files through the scrubber and records what it wrote."""

    def __init__(self, root: Path, scrub: Scrubber) -> None:
        self.root = root
        self.scrub = scrub
        self.files: list[dict[str, str]] = []

    def text(self, rel: str, content: str, purpose: str) -> Path:
        clean = safe_rel_subpath(rel)
        if not clean or not clean.startswith(f"{PASSPORT_DIR_NAME}/"):
            raise ValueError(f"Unsafe passport output path: {rel!r}")
        pdir_resolved = (self.root / PASSPORT_DIR_NAME).resolve()
        path = self.root / clean
        if path.is_symlink():
            raise ValueError(f"Refusing to write symlink: {rel!r}")
        resolved = path.resolve()
        if (
            not resolved.is_relative_to(pdir_resolved)
            or resolved == pdir_resolved
        ):
            raise ValueError(f"Passport output escapes passport/: {rel!r}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.scrub(content), encoding="utf-8")
        self.files.append({"path": clean, "purpose": purpose})
        return path


def scrub_agent_files(
    root: Path, files: list[Path], scrub: Scrubber
) -> tuple[list[str], list[dict[str, Any]]]:
    """Apply the placeholders to the agent files in place."""
    changed: list[str] = []
    portability: list[dict[str, Any]] = []
    for path in files:
        text = read_text(path)
        if text is None:
            continue
        new = scrub(text)
        if new == text:
            continue
        rel = str(path.relative_to(root))
        for idx, line in enumerate(text.splitlines(), start=1):
            if has_pinned_secret_version(line):
                portability.append(
                    {
                        "file": rel,
                        "line": idx,
                        "change": "secret version pinned in the source -> `latest` (version numbers do not carry over)",
                    }
                )
            for host, replacement in scrub.url_rewrites.items():
                if host in line:
                    portability.append(
                        {
                            "file": rel,
                            "line": idx,
                            "change": "Cloud Run URL in the generated `<service>-<hash>.a.run.app` form -> "
                            + (
                                "the same service's URL derived from the project number"
                                if replacement.startswith("http")
                                else f"placeholder `{replacement}`"
                            ),
                        }
                    )
        path.write_text(new, encoding="utf-8")
        changed.append(rel)
    return changed, portability


def scan_occurrences(
    root: Path, rel_paths: list[str]
) -> dict[str, list[tuple[str, int, str]]]:
    """Placeholder name -> [(file, line, line text)] over `rel_paths`."""
    found: dict[str, list[tuple[str, int, str]]] = {}
    for rel in rel_paths:
        text = read_text(root / rel)
        if text is None:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            for m in PLACEHOLDER_NAME_RE.finditer(line):
                stripped = line.strip()
                found.setdefault(m.group(1), []).append(
                    (
                        rel,
                        idx,
                        stripped
                        if len(stripped) <= 160
                        else stripped[:157] + "...",
                    )
                )
    for name, items in found.items():
        uniq: list[tuple[str, int, str]] = []
        for item in items:
            if item not in uniq:
                uniq.append(item)
        found[name] = uniq
    return found
