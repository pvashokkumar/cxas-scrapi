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

"""Unit tests for the helpers of the `cxas pull --passport` export.

MCP server config parsing and credential redaction, BigQuery table references
in SQL and Python tools, Cloud Run spec sanitizing and env redaction, the
BigQuery DDL of `schema.sql`, and the scrubber.
"""

from __future__ import annotations

import json
import re

import yaml
from passport_fakes import (
    SRC_PROJECT,
    TOOLS_YAML,
    knative_service,
    retail_tables,
)

from cxas_scrapi.utils.passport.mcp_config import (
    parse_mcp_config,
    redact_credentials,
)
from cxas_scrapi.utils.passport.model import BqDataset, BqTable, Scrubber
from cxas_scrapi.utils.passport.plugins.bigquery import schema_sql
from cxas_scrapi.utils.passport.render import md_cell, md_code
from cxas_scrapi.utils.passport.run_spec import (
    redact_plain_env,
    sanitize_knative_service,
)
from cxas_scrapi.utils.passport.scan import (
    Refs,
    scan_python_bigquery,
    sql_table_refs,
)


def test_redact_credentials_keeps_structure_and_env_references() -> None:
    text = (
        "sources:\n"
        "  pg:\n"
        "    kind: postgres\n"
        "    user: app\n"
        "    password: s3cr3t!\n"
        "    apiKey: ${API_KEY}\n"
        "    privateKey: |\n"
        "      -----BEGIN KEY-----\n"
        "      abc\n"
        "    host: db.example.com\n"
        "  other:\n"
        "    url: postgres://app:hunter2@db:5432/x\n"
    )
    redacted = redact_credentials(text)
    assert "s3cr3t" not in redacted
    assert "BEGIN KEY" not in redacted
    assert "hunter2" not in redacted
    # Whole values become double-quoted scalars, so any value can fill them in.
    assert 'password: "${REDACTED_PASSWORD}"' in redacted
    assert "apiKey: ${API_KEY}" in redacted  # already an env reference
    assert 'privateKey: "${REDACTED_PRIVATEKEY}"' in redacted
    assert "host: db.example.com" in redacted
    assert "user: app" in redacted
    assert "postgres://app:${REDACTED_URL_PASSWORD}@db:5432/x" in redacted
    assert re.findall(r"\$\{REDACTED_[A-Z_]+\}", redacted) == [
        "${REDACTED_PASSWORD}",
        "${REDACTED_PRIVATEKEY}",
        "${REDACTED_URL_PASSWORD}",
    ]
    parsed = yaml.safe_load(redacted)
    assert parsed["sources"]["pg"]["kind"] == "postgres"
    assert parsed["sources"]["pg"]["password"] == "${REDACTED_PASSWORD}"


def test_parse_mcp_config_both_layouts() -> None:
    sources, tools, toolsets = parse_mcp_config(TOOLS_YAML)
    assert sources["retail_bq"]["kind"] == "bigquery"
    assert tools["read_kb_object"]["source"] == "retail_kb"
    assert toolsets == {
        "retail_chat_agent": [
            "get_order_details",
            "search_products",
            "read_kb_object",
        ]
    }
    multi = (
        "kind: sources\nname: my-pg\ntype: postgres\nhost: h\n---\n"
        "kind: tools\nname: q\ntype: postgres-sql\nsource: my-pg\nstatement: SELECT 1\n"
    )
    sources, tools, _ = parse_mcp_config(multi)
    assert sources["my-pg"]["kind"] == "postgres"
    assert tools["q"]["kind"] == "postgres-sql"
    assert parse_mcp_config("just: a config\n") is None
    assert parse_mcp_config("- not\n- a mapping\n") is None


def test_sql_table_refs() -> None:
    sql = (
        "SELECT * FROM `p-1.ds.t1` JOIN ds2.t2 ON 1=1 "
        "LEFT JOIN `ds3.t3` x ON 1=1 JOIN `p-2`.ds4.t4 ON 1=1 "
        "JOIN `{expr}.t5` ON 1=1 JOIN ds.INFORMATION_SCHEMA.TABLES ON 1=1"
    )
    assert sql_table_refs(sql) == [
        ("p-1", "ds", "t1"),
        ("p-2", "ds4", "t4"),
        (None, "ds3", "t3"),
        (None, "ds2", "t2"),
    ]
    assert sql_table_refs("not sql `a.b.c`") == []


def test_python_tool_sql_resolves_the_dataset_constant() -> None:
    rel = "tools/lookup_account/python_function/python_code.py"
    code = (
        f'_DS = "{SRC_PROJECT}.billing"\n'
        "\n"
        "def lookup_account(acct: str) -> dict:\n"
        '    """Runs SELECT balance FROM `docs.only` for one account."""\n'
        '    q = f"SELECT balance FROM `{_DS}.accounts` WHERE id = @acct"\n'
        '    other = f"SELECT x FROM `{unknown}.t`"\n'
        '    return {"q": q, "other": other}\n'
    )
    refs = Refs()
    scan_python_bigquery(rel, code, refs)
    # The dataset constant, and the f-string rebuilt with it; never the
    # docstring, never an f-string part that is not a module constant.
    assert refs.bq == [
        (SRC_PROJECT, "billing", None, rel, 1),
        (SRC_PROJECT, "billing", "accounts", rel, 5),
    ]


def test_sanitize_knative_service_strips_server_fields() -> None:
    live = knative_service()
    live["spec"]["traffic"] = [
        {"revisionName": "r1", "percent": 50},
        {"latestRevision": True, "percent": 50},
    ]
    spec, notes = sanitize_knative_service(live)
    assert "status" not in spec
    assert "uid" not in spec["metadata"]
    assert "run.googleapis.com/urls" not in spec["metadata"]["annotations"]
    assert spec["spec"]["traffic"] == [{"percent": 100, "latestRevision": True}]
    assert any("split traffic" in n for n in notes)
    assert any("latest" in n for n in notes)
    assert (
        live["spec"]["template"]["spec"]["volumes"][0]["secret"]["items"][0][
            "key"
        ]
        == "1"
    )  # input untouched


def test_credential_like_env_values_are_redacted_in_the_service_spec() -> None:
    spec, _ = sanitize_knative_service(knative_service())
    container = spec["spec"]["template"]["spec"]["containers"][0]
    container["env"] = [
        {"name": "DB_PASSWORD", "value": "hunter2!"},
        {
            "name": "DATABASE_URL",
            "value": "postgres://app:s3cr3t@db.internal:5432/x",
        },
        {"name": "TOKEN_TTL_SECONDS", "value": "3600"},
        {"name": "LOG_LEVEL", "value": "info"},
        {
            "name": "API_KEY",
            "valueFrom": {"secretKeyRef": {"name": "crm-key", "key": "latest"}},
        },
    ]
    redactions = redact_plain_env(spec)
    assert [r["key"] for r in redactions] == [
        "DB_PASSWORD",
        "DATABASE_URL (password in URL)",
    ]
    env = {e["name"]: e for e in container["env"]}
    assert env["DB_PASSWORD"]["value"] == "${REDACTED_ENV_DB_PASSWORD}"
    assert (
        env["DATABASE_URL"]["value"]
        == "postgres://app:${REDACTED_ENV_DATABASE_URL_PASSWORD}@db.internal:5432/x"
    )
    assert env["TOKEN_TTL_SECONDS"]["value"] == "3600"  # not a secret
    assert env["LOG_LEVEL"]["value"] == "info"
    assert env["API_KEY"] == {
        "name": "API_KEY",
        "valueFrom": {"secretKeyRef": {"name": "crm-key", "key": "latest"}},
    }
    assert "hunter2" not in json.dumps(spec)
    assert "s3cr3t" not in json.dumps(spec)


def test_schema_sql_is_the_live_schema_as_ddl() -> None:
    ds = BqDataset(
        project=SRC_PROJECT,
        dataset="retail_support",
        location="US",
        resource={
            "description": "Demo data.",
            "labels": {"app": "retail-chat-agent"},
        },
        tables={
            name: BqTable(name=name, resource=res)
            for name, res in retail_tables().items()
        },
    )
    sql = schema_sql(ds)
    assert f"CREATE SCHEMA IF NOT EXISTS `{SRC_PROJECT}.retail_support`" in sql
    assert "location = 'US'" in sql
    assert "description = 'Demo data.'" in sql
    assert "labels = [('app', 'retail-chat-agent')]" in sql
    assert (
        f"CREATE TABLE IF NOT EXISTS `{SRC_PROJECT}.retail_support.orders` ("
        in sql
    )
    assert (
        "`order_id` STRING NOT NULL OPTIONS (description = 'Order number, e.g. ORD-1.')"
        in sql
    )
    assert "`tags` ARRAY<STRING>" in sql
    assert (
        "`shipping` STRUCT<`carrier` STRING, `delivered_at` TIMESTAMP>" in sql
    )
    assert "PARTITION BY `order_date`" in sql
    assert "CLUSTER BY `customer_id`" in sql
    assert "description = 'Order headers.'" in sql
    assert "`is_vip` BOOL" in sql
    assert "`visits` INT64" in sql
    assert "`unit_price` FLOAT64" in sql
    assert "description = 'Name \\'as sold\\'.'" in sql
    assert "INSERT" not in sql.upper()


def test_schema_sql_views_external_tables_and_partition_options() -> None:
    date_field = {"schema": {"fields": [{"name": "d", "type": "DATE"}]}}
    tables = {
        "daily": BqTable(
            name="daily",
            resource={
                **date_field,
                "timePartitioning": {
                    "type": "DAY",
                    "field": "d",
                    "expirationMs": "172800000",
                },
                "requirePartitionFilter": True,
            },
        ),
        "ingest": BqTable(
            name="ingest",
            resource={"timePartitioning": {"expirationMs": "soon"}},
        ),
        "v": BqTable(
            name="v",
            kind="VIEW",
            resource={"view": {"query": "SELECT 1;"}, "description": "A view."},
        ),
        "mv": BqTable(
            name="mv",
            kind="MATERIALIZED_VIEW",
            resource={
                **date_field,
                "materializedView": {"query": "SELECT d FROM ds.daily"},
                "timePartitioning": {"type": "DAY", "field": "d"},
                "clustering": {"fields": ["d"]},
            },
        ),
        "old": BqTable(
            name="old",
            kind="VIEW",
            resource={
                "view": {
                    "query": "SELECT 1\nFROM [p:ds.t]",
                    "useLegacySql": True,
                }
            },
        ),
        "ext": BqTable(name="ext", kind="EXTERNAL", resource={}),
    }
    sql = schema_sql(
        BqDataset(
            project="p",
            dataset="ds",
            resource={
                "defaultTableExpirationMs": "172800000",
                "defaultPartitionExpirationMs": "never",
            },
            tables=tables,
        )
    )
    # Dataset options: a numeric expiration is kept, any other value left out.
    assert (
        "CREATE SCHEMA IF NOT EXISTS `p.ds`\nOPTIONS (\n"
        "  default_table_expiration_days = 2\n);"
    ) in sql
    assert "never" not in sql
    assert (
        "CREATE TABLE IF NOT EXISTS `p.ds.daily` (\n  `d` DATE\n)\nPARTITION BY `d`\n"
        "OPTIONS (\n  partition_expiration_days = 2,\n  require_partition_filter = TRUE\n);"
    ) in sql
    # Ingestion-time partitions; an expiration that is not a number is left out.
    assert "PARTITION BY _PARTITIONDATE;" in sql
    assert "soon" not in sql
    assert (
        "CREATE VIEW IF NOT EXISTS `p.ds.v`\nOPTIONS (\n  description = 'A view.'\n)\n"
        "AS\nSELECT 1;"
    ) in sql
    assert (
        "CREATE MATERIALIZED VIEW IF NOT EXISTS `p.ds.mv`\nPARTITION BY `d`\n"
        "CLUSTER BY `d`\nAS\nSELECT d FROM ds.daily;"
    ) in sql
    assert (
        "-- old: legacy SQL view; recreate it by hand. Its query in the source:\n"
        "--   SELECT 1\n--   FROM [p:ds.t]"
    ) in sql
    assert "-- ext: external table in the source; not recreated here" in sql


def test_markdown_helpers_escape_cells_and_code_spans() -> None:
    assert md_code("a`b") == "`` a`b ``"
    assert md_code("plain") == "`plain`"
    assert md_cell("a|b\nc ") == "a\\|b c"


def test_scrubber_boundaries() -> None:
    scrub = Scrubber(
        "my-proj",
        "123456789012",
        {
            "svc-abc123def-uc.a.run.app": "https://svc-123456789012.us-central1.run.app"
        },
        {"kb": "GCS_BUCKET_KB"},
    )
    out = scrub(
        "gs://my-proj-kb/a my-proj.ds.t x@my-proj.iam.gserviceaccount.com my-proj2 "
        '123456789012 9123456789012 https://svc-abc123def-uc.a.run.app/mcp gs://kb/x "kb" '
        "projects/123456789012/secrets/s/versions/7"
    )
    assert out == (
        "gs://${GCP_PROJECT}-kb/a ${GCP_PROJECT}.ds.t x@${GCP_PROJECT}.iam.gserviceaccount.com my-proj2 "
        '${GCP_PROJECT_NUMBER} 9123456789012 https://svc-${GCP_PROJECT_NUMBER}.us-central1.run.app/mcp gs://${GCS_BUCKET_KB}/x "${GCS_BUCKET_KB}" '
        "projects/${GCP_PROJECT_NUMBER}/secrets/s/versions/latest"
    )
    assert scrub.leftovers("my-proj2") == ["my-proj"]
    assert scrub.force("my-proj2") == "${GCP_PROJECT}2"
