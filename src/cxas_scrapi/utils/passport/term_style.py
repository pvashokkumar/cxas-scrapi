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

"""Color grading for the Passport CLI summaries.

Statuses are colored only on an interactive terminal: pipes, files, CI logs
and tests get plain text. Honors the NO_COLOR (https://no-color.org) and
FORCE_COLOR conventions.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

_CODES = {
    "green": "32",
    "yellow": "33",
    "red": "31",
    "cyan": "36",
    "dim": "2",
    "bold": "1",
}

_STATUS_STYLES = {
    "READY": "green",
    "PASSED": "green",
    "MISSING": "red",
    "FAILED": "red",
    "MISCONFIGURED": "yellow",
    "SKIPPED": "yellow",
    "WARN": "yellow",
    "NOT_CHECKED": "dim",
}


def color_enabled(stream: TextIO | None = None) -> bool:
    """True when ANSI colors should be written to `stream` (default stdout)."""
    if os.environ.get("NO_COLOR"):
        return False
    force = os.environ.get("FORCE_COLOR", "")
    if force and force != "0":
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    target = sys.stdout if stream is None else stream
    isatty = getattr(target, "isatty", None)
    return bool(callable(isatty) and isatty())


def paint(text: str, style: str | None, enabled: bool) -> str:
    """`text` wrapped in the ANSI codes of `style` when `enabled`."""
    code = _CODES.get(style or "")
    if not enabled or not code or not text:
        return text
    return f"\033[{code}m{text}\033[0m"


def status_style(status: str) -> str | None:
    """Color of a status word: READY/PASSED green, MISSING/FAILED red, ..."""
    word = status.strip().split(" ", 1)[0].upper() if status else ""
    return _STATUS_STYLES.get(word)


def plural_noun(noun: str, count: int) -> str:
    """Pluralize a resource noun (`dataset` -> `datasets`)."""
    if count == 1:
        return noun
    word, sep, rest = noun.partition(" (")
    word = (
        word[:-1] + "ies"
        if word.endswith("y") and word[-2:-1] not in "aeiou"
        else word + "s"
    )
    return word + (sep + rest if sep else "")


def format_duration_ms(ms: float | int | None) -> str:
    """Format milliseconds into human-readable `ms` or `s`."""
    if ms is None:
        return "0 ms"
    try:
        val = float(ms)
    except (TypeError, ValueError):
        return f"{ms} ms"
    if val < 1000.0:
        return f"{round(val)} ms"
    return f"{val / 1000.0:.1f}s"
