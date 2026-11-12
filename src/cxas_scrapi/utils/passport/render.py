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

"""Text helpers of the passport files under `passport/`.

Markdown cells and code spans for the READMEs and PLACEHOLDERS.md, the
BigQuery DDL that `schema.sql` holds (from the live dataset and table
resources, schemas only), and the marker for YAML double-quoted strings.
Values in the text are raw source values; the export writes every file
through `passport.model.Scrubber`, which turns them into placeholders.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.model import BqDataset, BqTable

_NUM_LITERAL_RE = re.compile(r"^-?\d+(?:\.\d+)?$")

# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def md_code(value: Any) -> str:
    text = str(value)
    if "`" in text:
        return f"`` {text} ``"
    return f"`{text}`"


def md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


# --------------------------------------------------------------------------
# BigQuery
# --------------------------------------------------------------------------

_BQ_TYPE_ALIASES = {
    "INTEGER": "INT64",
    "FLOAT": "FLOAT64",
    "BOOLEAN": "BOOL",
    "RECORD": "STRUCT",
}


def sql_string(value: Any) -> str:
    text = str(value)
    text = (
        text.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f"'{text}'"


def bq_column_type(field: dict[str, Any]) -> str:
    raw = str(field.get("type") or "STRING").upper()
    ftype = _BQ_TYPE_ALIASES.get(raw, raw)
    if ftype == "STRUCT":
        inner = ", ".join(
            bq_column_def(sub) for sub in field.get("fields") or []
        )
        ftype = f"STRUCT<{inner}>"
    elif ftype in ("STRING", "BYTES") and field.get("maxLength"):
        ftype = f"{ftype}({field['maxLength']})"
    elif ftype in ("NUMERIC", "BIGNUMERIC") and field.get("precision"):
        scale = field.get("scale")
        ftype = f"{ftype}({field['precision']}{', ' + str(scale) if scale not in (None, '') else ''})"
    elif ftype == "RANGE":
        element = (field.get("rangeElementType") or {}).get("type") or "DATE"
        ftype = f"RANGE<{element}>"
    if str(field.get("mode") or "").upper() == "REPEATED":
        ftype = f"ARRAY<{ftype}>"
    return ftype


def bq_column_def(field: dict[str, Any]) -> str:
    parts = [f"`{field.get('name')}`", bq_column_type(field)]
    if field.get("defaultValueExpression"):
        parts.append(f"DEFAULT {field['defaultValueExpression']}")
    if str(field.get("mode") or "").upper() == "REQUIRED":
        parts.append("NOT NULL")
    if field.get("description"):
        parts.append(
            f"OPTIONS (description = {sql_string(field['description'])})"
        )
    return " ".join(parts)


def _bq_labels_option(labels: dict[str, Any] | None) -> str | None:
    if not labels:
        return None
    pairs = ", ".join(
        f"({sql_string(k)}, {sql_string(v)})" for k, v in sorted(labels.items())
    )
    return f"labels = [{pairs}]"


def _bq_partition_clause(
    resource: dict[str, Any],
) -> tuple[str | None, list[str]]:
    """PARTITION BY clause and extra table options for a live table resource."""
    options: list[str] = []
    time_p = resource.get("timePartitioning") or {}
    range_p = resource.get("rangePartitioning") or {}
    fields = {
        f.get("name"): str(f.get("type") or "").upper()
        for f in (resource.get("schema") or {}).get("fields") or []
    }
    clause = None
    if time_p:
        ptype = str(time_p.get("type") or "DAY").upper()
        column = time_p.get("field")
        if column:
            ctype = fields.get(column, "TIMESTAMP")
            if ptype == "DAY":
                clause = (
                    f"PARTITION BY `{column}`"
                    if ctype == "DATE"
                    else f"PARTITION BY DATE(`{column}`)"
                )
            elif ptype == "HOUR":
                func = (
                    "DATETIME_TRUNC"
                    if ctype == "DATETIME"
                    else "TIMESTAMP_TRUNC"
                )
                clause = f"PARTITION BY {func}(`{column}`, HOUR)"
            else:
                func = {"DATE": "DATE_TRUNC", "DATETIME": "DATETIME_TRUNC"}.get(
                    ctype, "TIMESTAMP_TRUNC"
                )
                clause = f"PARTITION BY {func}(`{column}`, {ptype})"
        elif ptype == "DAY":
            clause = "PARTITION BY _PARTITIONDATE"
        else:
            clause = f"PARTITION BY TIMESTAMP_TRUNC(_PARTITIONTIME, {ptype})"
        expiration_ms = str(time_p.get("expirationMs") or "")
        if expiration_ms.isdecimal():  # int64 milliseconds, as a string
            days = int(expiration_ms) / 86400000
            options.append(f"partition_expiration_days = {days:g}")
    elif range_p:
        rng = range_p.get("range") or {}
        clause = (
            f"PARTITION BY RANGE_BUCKET(`{range_p.get('field')}`, GENERATE_ARRAY("
            f"{rng.get('start', 0)}, {rng.get('end', 0)}, {rng.get('interval', 1)}))"
        )
    if resource.get("requirePartitionFilter") or time_p.get(
        "requirePartitionFilter"
    ):
        options.append("require_partition_filter = TRUE")
    return clause, options


def _bq_table_ref(ds: BqDataset, table: str) -> str:
    return f"`{ds.project}.{ds.dataset}.{table}`"


def _bq_table_ddl(ds: BqDataset, table: BqTable) -> str:
    res = table.resource or {}
    ref = _bq_table_ref(ds, table.ddl_name or table.name)
    prefix = (
        f"-- Table: {table.name}\n"
        if table.ddl_name and table.ddl_name != table.name
        else ""
    )
    description = res.get("description")
    labels_opt = _bq_labels_option(res.get("labels"))
    if table.kind in ("VIEW", "MATERIALIZED_VIEW"):
        view = (
            res.get("view" if table.kind == "VIEW" else "materializedView")
            or {}
        )
        query = str(view.get("query") or "").strip().rstrip(";")
        if view.get("useLegacySql"):
            return (
                f"-- {table.name}: legacy SQL view; recreate it by hand. Its query in the source:\n"
                + "\n".join(f"--   {line}" for line in query.splitlines())
            )
        options = []
        if description:
            options.append(f"description = {sql_string(description)}")
        if labels_opt:
            options.append(labels_opt)
        head = (
            "CREATE VIEW IF NOT EXISTS"
            if table.kind == "VIEW"
            else "CREATE MATERIALIZED VIEW IF NOT EXISTS"
        )
        extra = ""
        if table.kind == "MATERIALIZED_VIEW":
            clause, popts = _bq_partition_clause(res)
            if clause:
                extra += f"\n{clause}"
            cluster = (res.get("clustering") or {}).get("fields") or []
            if cluster:
                extra += "\nCLUSTER BY " + ", ".join(f"`{c}`" for c in cluster)
            options += popts
        opts = (
            "\nOPTIONS (\n  " + ",\n  ".join(options) + "\n)" if options else ""
        )
        return f"{prefix}{head} {ref}{extra}{opts}\nAS\n{query};"
    if table.kind in ("EXTERNAL", "SNAPSHOT"):
        return (
            f"-- {table.name}: {table.kind.lower()} table in the source; not recreated here "
            "(see README.md)."
        )
    fields = (res.get("schema") or {}).get("fields") or []
    cols = ",\n".join(f"  {bq_column_def(f)}" for f in fields)
    clause, options = _bq_partition_clause(res)
    tail = ""
    if clause:
        tail += f"\n{clause}"
    cluster = (res.get("clustering") or {}).get("fields") or []
    if cluster:
        tail += "\nCLUSTER BY " + ", ".join(f"`{c}`" for c in cluster)
    if description:
        options.insert(0, f"description = {sql_string(description)}")
    if labels_opt:
        options.append(labels_opt)
    if options:
        tail += "\nOPTIONS (\n  " + ",\n  ".join(options) + "\n)"
    return f"{prefix}CREATE TABLE IF NOT EXISTS {ref} (\n{cols}\n){tail};"


def _bq_dataset_options(ds: BqDataset) -> list[str]:
    res = ds.resource or {}
    options = []
    if ds.location:
        options.append(f"location = {sql_string(ds.location)}")
    if res.get("description"):
        options.append(f"description = {sql_string(res['description'])}")
    labels_opt = _bq_labels_option(res.get("labels"))
    if labels_opt:
        options.append(labels_opt)
    for key, option, divisor in (
        ("defaultTableExpirationMs", "default_table_expiration_days", 86400000),
        (
            "defaultPartitionExpirationMs",
            "default_partition_expiration_days",
            86400000,
        ),
    ):
        value = str(res.get(key) or "")
        if value.isdecimal():  # int64 milliseconds, as a string
            options.append(f"{option} = {int(value) / divisor:g}")
    if (
        res.get("maxTimeTravelHours")
        and str(res["maxTimeTravelHours"]) != "168"
    ):
        options.append(f"max_time_travel_hours = {res['maxTimeTravelHours']}")
    if res.get("isCaseInsensitive"):
        options.append("is_case_insensitive = TRUE")
    if res.get("storageBillingModel"):
        options.append(
            f"storage_billing_model = {sql_string(res['storageBillingModel'])}"
        )
    return options


def exported_tables(ds: BqDataset) -> list[BqTable]:
    """Tables that schema.sql creates (live schema known), tables before views."""
    order = {"TABLE": 0, "VIEW": 1, "MATERIALIZED_VIEW": 2}
    tables = [t for t in ds.tables.values() if t.resource and t.kind in order]
    return sorted(tables, key=lambda t: (order[t.kind], t.name))


def _bq_scalar_literal(v: Any, ftype: str, field: dict[str, Any]) -> str:
    if v is None:
        return "NULL"
    if ftype == "STRUCT" and isinstance(v, dict):
        subfields = field.get("fields") or []
        cells = v.get("f") or []
        inner = ", ".join(
            _bq_cell_literal(
                c.get("v") if isinstance(c, dict) else c,
                sf,
            )
            for c, sf in zip(cells, subfields, strict=False)
        )
        return f"STRUCT({inner})"
    text = str(v)
    if ftype in ("INT64", "FLOAT64", "NUMERIC", "BIGNUMERIC"):
        return text if _NUM_LITERAL_RE.match(text) else sql_string(text)
    if ftype == "BOOL":
        return "TRUE" if text.lower() in ("true", "1") else "FALSE"
    if ftype == "DATE":
        return f"DATE {sql_string(text)}"
    if ftype == "TIMESTAMP":
        if _NUM_LITERAL_RE.match(text):
            dt = datetime.fromtimestamp(float(text), tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            return f"TIMESTAMP {sql_string(dt)}"
        return f"TIMESTAMP {sql_string(text)}"
    if ftype == "JSON":
        return f"JSON {sql_string(text)}"
    return sql_string(text)


def _bq_cell_literal(value: Any, field: dict[str, Any]) -> str:
    if value is None:
        return "NULL"
    raw = str(field.get("type") or "STRING").upper()
    ftype = _BQ_TYPE_ALIASES.get(raw, raw)
    if str(field.get("mode") or "").upper() == "REPEATED" and isinstance(
        value, list
    ):
        items = ", ".join(
            _bq_scalar_literal(
                item.get("v") if isinstance(item, dict) else item, ftype, field
            )
            for item in value
        )
        return f"[{items}]"
    return _bq_scalar_literal(value, ftype, field)


def bq_seed_sql(ds: BqDataset) -> str:
    """INSERT statements for the prototype seed rows of `ds`."""
    blocks: list[str] = []
    for table in exported_tables(ds):
        if table.kind != "TABLE" or not table.rows:
            continue
        fields = ((table.resource or {}).get("schema") or {}).get(
            "fields"
        ) or []
        if not fields:
            continue
        cols = ", ".join(f"`{f.get('name')}`" for f in fields)
        tuples: list[str] = []
        for row in table.rows:
            cells = row.get("f") if isinstance(row, dict) else None
            if not isinstance(cells, list):
                continue
            vals = ", ".join(
                _bq_cell_literal(
                    c.get("v") if isinstance(c, dict) else c,
                    f,
                )
                for c, f in zip(cells, fields, strict=False)
            )
            tuples.append(f"  ({vals})")
        if not tuples:
            continue
        tuples.sort()
        ref = _bq_table_ref(ds, table.ddl_name or table.name)
        blocks.append(
            f"-- Seed data for table: {table.name} ({len(tuples)} row(s))\n"
            f"INSERT INTO {ref} ({cols})\nVALUES\n" + ",\n".join(tuples) + ";"
        )
    if not blocks:
        return ""
    head = (
        f"-- Prototype seed data for dataset `{ds.dataset}`, read from the live tables by\n"
        "-- `cxas pull --passport`.\n\n"
    )
    return head + "\n\n".join(blocks) + "\n"


# --------------------------------------------------------------------------
# Cloud Run
# --------------------------------------------------------------------------


class DoubleQuoted(str):
    """A string that service.yaml writes as a YAML double-quoted scalar.

    Used for environment values that hold a `${REDACTED_ENV_...}` placeholder,
    so that the value stays one quoted string when someone fills it in.
    """
