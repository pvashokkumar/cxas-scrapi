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

"""BigQuery datasets: location, settings and the schemas of the tables in use.

Never rows. Tables come from the agent's SQL (Python tools, MCP tool
statements); wildcard names (`events_*`) are matched against the dataset's
table list. All tables when the use is dataset-wide (an MCP tool that runs
any SQL). The CES conversation export writes one table per app, named after
the app ID: only this app's table is described, not other apps' tables in a
shared logging dataset.
"""

from __future__ import annotations

import fnmatch
import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import render
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import READ_ROLES, dataset_bindings
from cxas_scrapi.utils.passport.model import (
    BQ_DATASET_ID_TOKEN,
    BQ_TABLE_ID_TOKEN,
    BqDataset,
    BqTable,
)
from cxas_scrapi.utils.passport.plugins.base import Plugin

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://bigquery.googleapis.com/bigquery/v2"
MAX_TABLES = 500
MAX_PATTERN_TABLES = (
    20  # date-sharded tables share a schema: the newest few say it all
)
MAX_SEED_ROWS = 100


def _sanitize_dataset(data: dict[str, Any], project: str) -> dict[str, Any]:
    out = {k: v for k, v in data.items() if k != "access"}
    if "id" in out:
        out["id"] = f"{project}:{BQ_DATASET_ID_TOKEN}"
    if "selfLink" in out:
        out["selfLink"] = (
            f"{API}/projects/{project}/datasets/{BQ_DATASET_ID_TOKEN}"
        )
    ref = out.get("datasetReference")
    if isinstance(ref, dict):
        out["datasetReference"] = {**ref, "datasetId": BQ_DATASET_ID_TOKEN}
    return out


def _sanitize_table(data: dict[str, Any], project: str) -> dict[str, Any]:
    out = dict(data)
    if "id" in out:
        out["id"] = f"{project}:{BQ_DATASET_ID_TOKEN}.{BQ_TABLE_ID_TOKEN}"
    if "selfLink" in out:
        out["selfLink"] = (
            f"{API}/projects/{project}/datasets/{BQ_DATASET_ID_TOKEN}/tables/{BQ_TABLE_ID_TOKEN}"
        )
    ref = out.get("tableReference")
    if isinstance(ref, dict):
        out["tableReference"] = {
            **ref,
            "datasetId": BQ_DATASET_ID_TOKEN,
            "tableId": BQ_TABLE_ID_TOKEN,
        }
    return out


class BigQueryDatasetPlugin(Plugin):
    kind = "bigquery.dataset"
    service = "BigQuery"
    noun = "dataset"
    folder = "bigquery"

    def _url(self, node: Node, suffix: str = "") -> str:
        project, dataset = node.ref.id.split("/")[1], node.ref.id.split("/")[3]
        return f"{API}/projects/{project}/datasets/{dataset}{suffix}"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        project = node.ref.id.split("/")[1]
        data = ctx.reader.get(self._url(node), area=self.kind)
        node.iam = dataset_bindings(data)
        node.config = _sanitize_dataset(data, project)
        node.location = data.get("location") or node.location
        node.extras.setdefault("tables", {})
        node.extras.setdefault("table_rows", {})
        node.extras.setdefault("missing_tables", [])

    def details(self, node: Node, ctx: WalkContext) -> None:
        if "conversation logging" in node.purposes and not node.whole:
            return
        project = node.ref.id.split("/")[1]
        tables: dict[str, Any] = node.extras["tables"]
        table_rows: dict[str, list[dict[str, Any]]] = node.extras.setdefault(
            "table_rows", {}
        )
        fetched: set[str] = node.extras.setdefault("fetched_tables", set())
        pending = node.scope - node.scope_done - fetched
        patterns = sorted(name for name in pending if "*" in name)
        wanted = {name for name in pending if "*" not in name}
        whole = node.whole and not node.whole_done
        if whole or patterns:
            try:
                listed = self._list_tables(node, ctx)
            except NotReadable as exc:
                ctx.read_failed(
                    exc,
                    kind=self.kind,
                    rid=f"{node.ref.id}/tables",
                    what="table list",
                    role=READ_ROLES["bigquery.table"],
                    owner=node.ref,
                    impact="the tables of a dataset-wide use or of wildcard names (`events_*`) are not described",
                )
                listed = []
            if whole:
                wanted |= set(listed)
            for pattern in patterns:
                wanted |= self._matching(node, listed, pattern)
        to_fetch = sorted(wanted - fetched)
        for name in to_fetch:
            try:
                table = ctx.reader.get(
                    self._url(node, f"/tables/{urllib.parse.quote(name)}"),
                    area=self.kind,
                )
            except NotReadable as exc:
                if exc.category == "not_found":
                    node.extras["missing_tables"].append(name)
                else:
                    ctx.read_failed(
                        exc,
                        kind="bigquery.table",
                        rid=f"{node.ref.id}/tables/{name}",
                        what=f"schema of table `{name}`",
                        role=READ_ROLES["bigquery.table"],
                        owner=node.ref,
                    )
                continue
            fetched.add(name)
            tables[name] = _sanitize_table(table, project)
            self._read_seed_rows(node, ctx, name, table, table_rows)

    def _read_seed_rows(
        self,
        node: Node,
        ctx: WalkContext,
        name: str,
        table: dict[str, Any],
        table_rows: dict[str, list[dict[str, Any]]],
    ) -> None:
        if "conversation logging" in node.purposes:
            return
        if str(table.get("type") or "TABLE").upper() != "TABLE":
            return
        raw_rows = str(table.get("numRows") or "0")
        if not raw_rows.isdigit():
            return
        num_rows = int(raw_rows)
        if num_rows <= 0:
            return
        if num_rows > MAX_SEED_ROWS:
            node.notes.append(
                f"Table `{name}` has {num_rows} rows (> {MAX_SEED_ROWS}): seed rows are not exported in `seed.sql`."
            )
            return
        try:
            data = ctx.reader.get(
                self._url(
                    node,
                    f"/tables/{urllib.parse.quote(name)}/data?maxResults={MAX_SEED_ROWS}",
                ),
                area=self.kind,
            )
        except NotReadable:
            return
        rows = data.get("rows")
        if isinstance(rows, list) and rows:
            table_rows[name] = rows

    def _matching(
        self, node: Node, listed: list[str], pattern: str
    ) -> set[str]:
        """The tables a wildcard name (`events_*`, `<app id>*`) stands for."""
        matches = sorted(t for t in listed if fnmatch.fnmatchcase(t, pattern))
        if not matches:
            node.notes.append(
                f"No table of the dataset matches `{pattern}` yet."
            )
        elif len(matches) > MAX_PATTERN_TABLES:
            node.notes.append(
                f"{len(matches)} tables match `{pattern}`: only the last "
                f"{MAX_PATTERN_TABLES} by name are described."
            )
            matches = matches[-MAX_PATTERN_TABLES:]
        return set(matches)

    def _list_tables(self, node: Node, ctx: WalkContext) -> list[str]:
        names: list[str] = []
        token = ""
        while len(names) < MAX_TABLES:
            suffix = "/tables?maxResults=1000" + (
                f"&pageToken={urllib.parse.quote(token)}" if token else ""
            )
            data = ctx.reader.get(self._url(node, suffix), area=self.kind)
            for item in data.get("tables") or []:
                table_id = ((item or {}).get("tableReference") or {}).get(
                    "tableId"
                )
                if table_id:
                    names.append(str(table_id))
            token = str(data.get("nextPageToken") or "")
            if not token:
                break
        if len(names) >= MAX_TABLES:
            node.notes.append(f"Only the first {MAX_TABLES} tables are listed.")
        return names[:MAX_TABLES]

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        project, dataset = node.ref.id.split("/")[1], node.ref.id.split("/")[3]
        return dataset if ctx.is_source(project) else f"{project}.{dataset}"

    def _model(self, node: Node) -> BqDataset:
        project, dataset = node.ref.id.split("/")[1], node.ref.id.split("/")[3]
        table_rows = node.extras.get("table_rows") or {}
        ds = BqDataset(
            project=project,
            dataset=dataset,
            location=node.location,
            resource=node.config,
            purpose="conversation_export"
            if "conversation logging" in node.purposes
            else "data",
        )
        for name, res in sorted(node.extras.get("tables", {}).items()):
            ds.tables[name] = BqTable(
                name=name,
                kind=str(res.get("type") or "TABLE").upper(),
                resource=res,
                ddl_name=name,
                rows=table_rows.get(name, []),
            )
        return ds

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        model = self._model(node)
        out = {
            "schema.sql": (
                schema_sql(model),
                "the live schema as DDL",
            )
        }
        seed = render.bq_seed_sql(model)
        if seed:
            out["seed.sql"] = (
                seed,
                "prototype seed rows from the live tables",
            )
        return out

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        tables = node.extras.get("tables", {})
        return [
            ("Used for", node.purposes or ["data the agent reads"]),
            ("Location", node.location),
            ("Description", cfg.get("description")),
            ("Labels", cfg.get("labels")),
            (
                "Default table expiration ms",
                cfg.get("defaultTableExpirationMs"),
            ),
            (
                "Tables in use",
                [
                    f"{name} ({len(((res.get('schema') or {}).get('fields')) or [])} columns, {str(res.get('type') or 'TABLE').lower()})"
                    for name, res in sorted(tables.items())
                ],
            ),
            (
                "Tables the agent names but the dataset lacks",
                node.extras.get("missing_tables"),
            ),
            ("All tables listed (dataset-wide use)", node.whole),
        ]

    def summary(self, node: Node) -> dict[str, Any]:
        tables = node.extras.get("tables", {})
        return {
            "location": node.location,
            "purposes": node.purposes,
            "tables": [
                {
                    "name": name,
                    "type": str(res.get("type") or "TABLE").upper(),
                    "columns": len(
                        ((res.get("schema") or {}).get("fields")) or []
                    ),
                }
                for name, res in sorted(tables.items())
            ],
            "missing_tables": node.extras.get("missing_tables") or [],
            "dataset_wide_use": node.whole,
        }


def schema_sql(ds: BqDataset) -> str:
    """DDL of the dataset and its tables from the live resources."""
    lines = [
        f"-- BigQuery schema of dataset `{ds.dataset}`, read from the live dataset by",
        "-- `cxas pull --passport`. Schema only: no rows.",
        "",
    ]
    options = render._bq_dataset_options(ds)
    head = f"CREATE SCHEMA IF NOT EXISTS `{ds.project}.{ds.dataset}`"
    if options:
        head += "\nOPTIONS (\n  " + ",\n  ".join(options) + "\n)"
    lines += [head + ";", ""]
    if ds.purpose == "conversation_export":
        lines += [
            "-- CES creates the conversation export table automatically when logging conversations.",
        ]
        return "\n".join(lines).rstrip("\n") + "\n"
    exported = render.exported_tables(ds)
    for table in exported:
        lines += [render._bq_table_ddl(ds, table), ""]
    for table in sorted(ds.tables.values(), key=lambda t: t.name):
        if table not in exported:
            lines += [render._bq_table_ddl(ds, table), ""]
    return "\n".join(lines).rstrip("\n") + "\n"
