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

"""What an earlier `cxas pull --passport` left in the same folder."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cxas_scrapi.utils.passport.files import read_json, read_text
from cxas_scrapi.utils.passport.model import (
    GCP_PROJECT_NUMBER_TOKEN,
    GCP_PROJECT_TOKEN,
    PASSPORT_DIR_NAME,
    PASSPORT_LEDGER_NAME,
    PASSPORT_MANIFEST_NAME,
    PLACEHOLDER_NAME_RE,
    PLACEHOLDERS_GUIDE_NAME,
)

if TYPE_CHECKING:
    from pathlib import Path


def _remove_empty_dirs(base: Path) -> None:
    """Remove the empty folders below `base` (deepest first), and `base` if empty."""
    if not base.is_dir():
        return
    for path in sorted(base.rglob("*"), key=lambda p: -len(p.parts)):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    if not any(base.iterdir()):
        base.rmdir()


def remove_previous_passport(root: Path) -> list[str]:
    """Remove what an earlier `cxas pull --passport` into this folder wrote.

    Only files a passport export generates are removed (the previous manifest
    lists them); push ledgers and unknown files stay.
    """
    removed: list[str] = []
    guide = root / PLACEHOLDERS_GUIDE_NAME
    if guide.is_file():
        guide.unlink()
        removed.append(PLACEHOLDERS_GUIDE_NAME)

    pdir = root / PASSPORT_DIR_NAME
    if not pdir.is_dir():
        return removed
    pdir_resolved = pdir.resolve()
    manifest_file = pdir / PASSPORT_MANIFEST_NAME
    previous = read_json(manifest_file)
    listed = [
        str(item.get("path") or "")
        for item in previous.get("files") or []
        if isinstance(item, dict)
    ]
    for rel in listed:
        if not rel.startswith(f"{PASSPORT_DIR_NAME}/") or rel.endswith(
            PASSPORT_LEDGER_NAME
        ):
            continue
        raw_path = root / rel
        if raw_path.is_symlink():
            continue
        resolved = raw_path.resolve()
        if (
            not resolved.is_relative_to(pdir_resolved)
            or resolved == pdir_resolved
        ):
            continue
        if resolved.is_file():
            resolved.unlink()
            removed.append(rel)
    manifest_rel = f"{PASSPORT_DIR_NAME}/{PASSPORT_MANIFEST_NAME}"
    if manifest_file.is_file() and not manifest_file.is_symlink():
        manifest_file.unlink()
        if manifest_rel not in removed:
            removed.append(manifest_rel)
    for sub in sorted(p for p in pdir.iterdir() if p.is_dir()):
        _remove_empty_dirs(sub)
    return removed


def restore_source_values(
    files: list[Path], project_id: str | None, project_number: str | None
) -> tuple[bool, list[str]]:
    """Put the source project values back into files an earlier export scrubbed.

    `cxas pull` extracts the app again (with its real values) before the export
    runs, so this only matters when the export runs twice over the same folder.
    Returns (whether any file changed, placeholder names still in the files):
    the source value of a bucket or `${CLOUD_RUN_URL_...}` placeholder is not
    known here.
    """
    changed = False
    left: set[str] = set()
    for path in files:
        text = read_text(path)
        if text is None or "${" not in text:
            continue
        new = text
        if project_number:
            new = new.replace(GCP_PROJECT_NUMBER_TOKEN, project_number)
        if project_id:
            new = new.replace(GCP_PROJECT_TOKEN, project_id)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed = True
        left.update(
            m.group(1)
            for m in PLACEHOLDER_NAME_RE.finditer(new)
            if not m.group(1).startswith("REDACTED_")
        )
    return changed, sorted(left)
