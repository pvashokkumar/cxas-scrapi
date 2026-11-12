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

"""BigQuery tables named in SQL text, and the string literals of Python code."""

from __future__ import annotations

import ast
import re

_SQL_HINT_RE = re.compile(
    r"(?is)\b(select|insert|update|delete|merge|create)\b"
)
_BQ_BACKTICK3_RE = re.compile(
    r"`(?P<project>[A-Za-z][A-Za-z0-9_.:-]*)\.(?P<dataset>[A-Za-z_][A-Za-z0-9_]*)\.(?P<table>[A-Za-z_][A-Za-z0-9_$*-]*)`"
)
_BQ_SPLIT_BACKTICK_RE = re.compile(
    r"`(?P<project>[A-Za-z][A-Za-z0-9_.:-]*)`\.`?(?P<dataset>[A-Za-z_][A-Za-z0-9_]*)`?\.`?(?P<table>[A-Za-z_][A-Za-z0-9_$*]*)`?"
)
_BQ_BACKTICK2_RE = re.compile(
    r"`(?P<dataset>[A-Za-z_][A-Za-z0-9_]*)\.(?P<table>[A-Za-z_][A-Za-z0-9_$*]*)`"
)
_BQ_UNQUOTED_RE = re.compile(
    r"(?i)\b(?:from|join|into|update|merge(?:\s+into)?|table)\s+(?:(?P<project>[A-Za-z][A-Za-z0-9_-]*)\.)?(?P<dataset>[A-Za-z_][A-Za-z0-9_]*)\.(?P<table>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_NOT_PROJECTS = {
    "self",
    "cls",
    "client",
    "bq",
    "db",
    "os",
    "sys",
    "re",
    "json",
    "session_state",
    "context",
    "data",
}
DATASET_CONST_NAMES = {
    "_DS",
    "DATASET",
    "BQ_DATASET",
    "_DATASET",
    "DATASET_ID",
    "BQ_DS",
}


def python_strings(text: str) -> list[tuple[str, int]]:
    """Non-docstring string literals of a Python file, f-strings rebuilt with module constants."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    consts: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = node.value.value
    doc_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_ids.add(id(body[0].value))
    out: list[tuple[str, int]] = []
    joined_parts: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            pieces = []
            for value in node.values:
                joined_parts.add(id(value))
                if isinstance(value, ast.Constant) and isinstance(
                    value.value, str
                ):
                    pieces.append(value.value)
                elif (
                    isinstance(value, ast.FormattedValue)
                    and isinstance(value.value, ast.Name)
                    and value.value.id in consts
                ):
                    pieces.append(consts[value.value.id].strip("`"))
                else:
                    pieces.append("{expr}")
            out.append(("".join(pieces), getattr(node, "lineno", 1)))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in doc_ids
            and id(node) not in joined_parts
        ):
            out.append((node.value, getattr(node, "lineno", 1)))
    return out


def sql_table_refs(sql: str) -> list[tuple[str | None, str, str]]:
    """(project or None, dataset, table) referenced by a BigQuery SQL text."""
    if not _SQL_HINT_RE.search(sql):
        return []
    found: list[tuple[str | None, str, str]] = []
    spans: list[tuple[int, int]] = []

    def _add(
        project: str | None, dataset: str, table: str, span: tuple[int, int]
    ) -> None:
        if any(s <= span[0] < e for s, e in spans):
            return
        if "{" in (project or "") or "{" in dataset or "{" in table:
            return
        if (
            dataset.upper() == "INFORMATION_SCHEMA"
            or table.upper() == "INFORMATION_SCHEMA"
        ):
            return
        if project and (
            project.lower() in _NOT_PROJECTS
            or project.lower().startswith("region-")
        ):
            return
        spans.append(span)
        item = (project, dataset, table)
        if item not in found:
            found.append(item)

    for m in _BQ_BACKTICK3_RE.finditer(sql):
        _add(m.group("project"), m.group("dataset"), m.group("table"), m.span())
    for m in _BQ_SPLIT_BACKTICK_RE.finditer(sql):
        _add(m.group("project"), m.group("dataset"), m.group("table"), m.span())
    for m in _BQ_BACKTICK2_RE.finditer(sql):
        _add(None, m.group("dataset"), m.group("table"), m.span())
    for m in _BQ_UNQUOTED_RE.finditer(sql):
        _add(m.group("project"), m.group("dataset"), m.group("table"), m.span())
    return found
