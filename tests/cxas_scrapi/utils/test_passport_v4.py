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

"""Passport layout v4: a usage-scoped walk over the agent's Google Cloud resources.

The fake cloud answers like the real REST APIs (passport_v4_cloud); the
export runs unchanged on top of it.
"""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING

from passport_v4_cloud import BQ, DS, FN, GCS, RUN_KN, FakeCloud, default_routes
from passport_v4_pull import pull_world
from passport_v4_resources import api_disabled, function_service, table
from passport_v4_world import (
    APP_ID,
    ENCODED_PROJECT,
    NUMBER,
    OTHER_APP_ID,
    PERSON,
    PLAIN_SECRET,
    PROJECT,
    TEAM,
    app_files,
)

from cxas_scrapi.utils.passport import push as passport_import
from cxas_scrapi.utils.passport.http import ApiReader
from cxas_scrapi.utils.passport.readiness import (
    audit_target_readiness,
    format_readiness_report,
)

if TYPE_CHECKING:
    from pathlib import Path

EXPECTED_FOLDERS = {
    "bigquery.dataset": {
        "passport/bigquery/conv_logs",
        "passport/bigquery/orders_ds",
    },
    "run.service": {
        "passport/cloud_run/order-toolbox",
    },
    "storage.bucket": {"passport/cloud_storage/kb"},
    "secretmanager.secret": {
        "passport/secret_manager/toolbox-config",
        "passport/secret_manager/loyalty-api-key",
    },
    "discoveryengine.dataStore": {"passport/vertex_ai_search/policy-docs"},
    "cloudfunctions.function": {"passport/cloud_functions/loyalty-api"},
    "iam.serviceAccount": {
        "passport/iam/order-toolbox-sa",
        "passport/iam/loyalty-fn-sa",
    },
}


def test_walk_reads_every_attached_kind_live(tmp_path: Path) -> None:
    pull = pull_world(tmp_path)
    found: dict[str, set[str]] = {}
    for res in pull.report["resources"]:
        assert res["status"] == "read", res
        found.setdefault(res["kind"], set()).add(res["folder"])
    assert found == EXPECTED_FOLDERS
    assert pull.cloud.unrouted == []
    manifest = pull.manifest()
    assert manifest["schema_version"] == "4.0"
    assert manifest["bundle_layout"] == "passport-v4"
    assert set(manifest["resources"]) == {
        "bigquery",
        "cloud_run",
        "cloud_storage",
        "secret_manager",
        "vertex_ai_search",
        "cloud_functions",
        "iam",
    }
    assert manifest["not_readable"] == []
    assert manifest["introspection"]["live"] is True
    assert [d["name"] for d in manifest["resources"]["bigquery"]] == [
        "conv_logs",
        "orders_ds",
    ]
    assert all("dataset" not in d for d in manifest["resources"]["bigquery"])
    assert all(
        "bucket" not in b for b in manifest["resources"]["cloud_storage"]
    )
    assert all(
        "secret" not in s for s in manifest["resources"]["secret_manager"]
    )
    run = {
        s["service"]: s["region"] for s in manifest["resources"]["cloud_run"]
    }
    assert run == {"order-toolbox": "us-central1"}


def test_bundle_is_metadata_only_with_live_details(tmp_path: Path) -> None:
    pull = pull_world(tmp_path)
    files = pull.files()
    assert not [f for f in files if f.endswith(".sh") or "template" in f]
    orders = "passport/bigquery/orders_ds"
    assert {f for f in files if f.startswith(orders + "/")} == {
        f"{orders}/schema.sql",
        f"{orders}/seed.sql",
    }
    conv_logs = "passport/bigquery/conv_logs"
    assert {f for f in files if f.startswith(conv_logs + "/")} == {
        f"{conv_logs}/schema.sql",
    }
    assert "CREATE TABLE" not in files[f"{conv_logs}/schema.sql"]
    schema = files[f"{orders}/schema.sql"]
    assert "CREATE SCHEMA IF NOT EXISTS `${GCP_PROJECT}.orders_ds`" in schema
    assert (
        "CREATE TABLE IF NOT EXISTS `${GCP_PROJECT}.orders_ds.orders`" in schema
    )
    assert "customer_id" in schema
    assert "audit_log" not in schema
    seed = files[f"{orders}/seed.sql"]
    assert "INSERT INTO `${GCP_PROJECT}.orders_ds.orders`" in seed
    assert "'ORD-1'" in seed
    assert "'maya@example.com'" in seed
    tools_yaml = files["passport/cloud_run/order-toolbox/tools.yaml"]
    assert "get_order" in tools_yaml
    assert "${GCP_PROJECT}.orders_ds.orders" in tools_yaml
    kb_doc = files["passport/cloud_storage/kb/files/policies/returns.md"]
    assert "# Return policy for ${GCP_PROJECT}" in kb_doc
    ds_bundle = json.loads(
        files["passport/vertex_ai_search/policy-docs/data_store.json"]
    )
    assert (
        ds_bundle["documents"][0]["uri"]
        == "gs://${GCP_PROJECT}-kb/policies/returns.md"
    )
    function = json.loads(
        files["passport/cloud_functions/loyalty-api/function.json"]
    )
    assert function["buildConfig"]["runtime"] == "python312"
    fn_main = files["passport/cloud_functions/loyalty-api/main.py"]
    assert 'PROJECT = "${GCP_PROJECT}"' in fn_main
    assert (
        "functions-framework"
        in files["passport/cloud_functions/loyalty-api/requirements.txt"]
    )
    assert "passport/cloud_run/loyalty-api/service.yaml" not in files
    assert "passport/secret_manager/loyalty-api-key/secret.json" not in files
    guide = files["PLACEHOLDERS.md"]
    for label in (
        "Vertex AI Search data store `policy-docs`",
        "Cloud Functions function `loyalty-api`",
    ):
        assert label in guide


def test_walk_is_scoped_to_what_the_agent_uses(tmp_path: Path) -> None:
    pull = pull_world(tmp_path)
    urls = pull.cloud.urls()
    # SQL names two tables of orders_ds: no listing, no third table.
    assert not pull.cloud.urls(f"{BQ}/orders_ds/tables?")
    assert not pull.cloud.urls("audit_log")
    # The tool no agent uses is not followed.
    assert not pull.cloud.urls("other_ds")
    assert pull.manifest()["agent"]["unused_tools"] == ["unused_tool"]
    # The logging dataset only needs CREATE SCHEMA IF NOT EXISTS; CES creates
    # the runtime log table automatically, so no log tables are listed or read.
    assert not pull.cloud.urls(f"{BQ}/conv_logs/tables")
    assert not pull.cloud.urls(OTHER_APP_ID)
    (logs,) = [
        e
        for e in pull.manifest()["resources"]["bigquery"]
        if e["name"] == "conv_logs"
    ]
    assert logs["live"]["tables"] == []
    assert logs["live"]["dataset_wide_use"] is False
    assert OTHER_APP_ID not in json.dumps(pull.files())
    assert APP_ID not in json.dumps(
        {
            k: v
            for k, v in pull.files().items()
            if k.startswith("passport/bigquery/")
        }
    )
    # Gen 2 Cloud Function is read once (including its backing Cloud Run annotation) without duplicating its Cloud Run node.
    assert urls.count(FN) == 1
    assert len(pull.cloud.urls(f"{RUN_KN}/loyalty-api")) == 1
    assert [
        s["service"] for s in pull.manifest()["resources"]["cloud_run"]
    ] == ["order-toolbox"]


def test_wildcard_tables_are_matched_against_the_table_list(
    tmp_path: Path,
) -> None:
    rel = "tools/lookup_order/python_function/python_code.py"
    code = app_files()[rel] + (
        f'_EVENTS = "SELECT * FROM `{PROJECT}.orders_ds.events_*`"\n'
    )
    routes = default_routes()
    names = ["audit_log", "customers", "events_20260101", "events_20260102"]
    routes[("GET", f"{BQ}/orders_ds/tables")] = (
        200,
        {"tables": [{"tableReference": {"tableId": n}} for n in names]},
    )
    for name in names[2:]:
        tbl = table("orders_ds", name, ["event_id", "event_time"])
        tbl["numRows"] = "0"
        routes[("GET", f"{BQ}/orders_ds/tables/{name}")] = (200, tbl)
    pull = pull_world(tmp_path, routes, files={rel: code})
    assert pull.cloud.unrouted == []
    files = pull.files()
    # `orders` and `events_*` come from the same file: both join the scope
    schema = files["passport/bigquery/orders_ds/schema.sql"]
    assert "`order_id` STRING" in schema
    assert schema.count("`event_id` STRING") == 2
    assert not pull.cloud.urls("audit_log")


def test_recording_bucket_objects_are_never_listed(tmp_path: Path) -> None:
    app = json.loads(app_files()["app.json"])
    app["loggingSettings"]["audioRecordingConfig"] = {
        "gcsBucket": f"gs://{PROJECT}-audio/recordings/"
    }
    audio = f"{GCS}/{PROJECT}-audio"
    routes = default_routes()
    routes[("GET", audio)] = (
        200,
        {"name": f"{PROJECT}-audio", "projectNumber": NUMBER, "location": "US"},
    )
    routes[("GET", f"{audio}/iam")] = (200, {"bindings": []})
    pull = pull_world(
        tmp_path, routes, files={"app.json": json.dumps(app, indent=2) + "\n"}
    )
    assert pull.cloud.unrouted == []
    assert pull.cloud.urls(audio)
    assert not pull.cloud.urls(
        f"{audio}/o"
    )  # conversation recordings stay unlisted
    assert pull.statuses("storage.bucket") == {"read"}


def test_bundle_holds_no_project_ids_people_or_credentials(
    tmp_path: Path,
) -> None:
    pull = pull_world(tmp_path)
    raw_values = (PROJECT, NUMBER, ENCODED_PROJECT, PERSON, TEAM, PLAIN_SECRET)
    for rel, text in pull.files().items():
        for raw in raw_values:
            assert raw not in text, (rel, raw)
    assert pull.report["raw_values_force_scrubbed"] == []
    run_iam = pull.manifest()["resources"]["cloud_run"][0]["iam"]
    assert run_iam["people_and_groups_not_listed"] == 1
    assert "REDACTED_ENV_API_TOKEN" in pull.text(
        "passport/cloud_run/order-toolbox/service.yaml"
    )


def test_agent_files_render_back_to_the_plain_pull(tmp_path: Path) -> None:
    pull = pull_world(tmp_path)
    files = pull.files()
    original = app_files()
    extra = set(files) - set(original)
    assert all(
        f == "PLACEHOLDERS.md" or f.startswith("passport/") for f in extra
    )
    for rel, text in original.items():
        rendered = (
            files[rel]
            .replace("${GCP_PROJECT_NUMBER}", NUMBER)
            .replace("${GCP_PROJECT}", PROJECT)
        )
        assert rendered == text, rel
    assert (
        "${GCP_PROJECT_NUMBER}"
        in files["toolsets/order_toolbox/order_toolbox.json"]
    )


def test_pull_is_read_only_and_uses_quota_project_only_where_needed(
    tmp_path: Path,
) -> None:
    pull = pull_world(tmp_path)
    for method, url, _ in pull.cloud.requests:
        assert method == "GET" or url.endswith(":getIamPolicy"), (method, url)
        assert "serviceusage" not in url
    assert pull.manifest()["introspection"]["read_only"] is True
    store = [(u, h) for _, u, h in pull.cloud.requests if u.startswith(DS)]
    assert store[0] == (DS, None)  # first try without, refused
    assert all(h == {"x-goog-user-project": PROJECT} for _, h in store[1:])
    others = [h for _, u, h in pull.cloud.requests if not u.startswith(DS)]
    assert others == [None] * len(others)


def test_offline_pull_reads_nothing_and_writes_readmes(tmp_path: Path) -> None:
    pull = pull_world(tmp_path, live=False)
    assert pull.cloud.requests == []
    statuses = {r["kind"]: r["status"] for r in pull.report["resources"]}
    assert set(statuses.values()) == {"not_read_offline"}
    # only what the agent files name: no runtime dependencies without live reads
    assert set(statuses) == {
        "bigquery.dataset",
        "run.service",
        "storage.bucket",
        "secretmanager.secret",
        "discoveryengine.dataStore",
        "cloudfunctions.function",
    }
    passport = [f for f in pull.files() if f.startswith("passport/")]
    assert all(
        f.endswith("README.md") or f == "passport/manifest.json"
        for f in passport
    )


def test_v4_bundle_pushes_through_the_placeholder_index(tmp_path: Path) -> None:
    pull = pull_world(tmp_path)
    staging = tmp_path / "staging"
    for rel in ("app.json", "environment.json", "agents", "tools", "toolsets"):
        src = pull.app / rel
        if src.is_dir():
            shutil.copytree(src, staging / rel)
        else:
            staging.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, staging / rel)
    report = passport_import.prepare_passport_push(
        staging_dir=staging,
        source_app_dir=pull.app,
        target_project_id="tgt-proj-456",
        target_location="us",
        strict_gates=False,
        project_number_resolver=lambda pid: (
            "999888777666" if pid == "tgt-proj-456" else None
        ),
    )
    assert report["bundle_layout"] == "passport-v4"
    assert report["unresolved_placeholders"] == []
    staged = {
        str(p.relative_to(staging)): p.read_text(encoding="utf-8")
        for p in staging.rglob("*")
        if p.is_file()
    }
    assert not [rel for rel, text in staged.items() if "${" in text]
    toolset = json.loads(staged["toolsets/order_toolbox/order_toolbox.json"])
    assert toolset["mcpToolset"]["serverAddress"] == (
        "https://order-toolbox-999888777666.us-central1.run.app/mcp"
    )
    env = json.loads(staged["environment.json"])
    logging = env["app"]["loggingSettings"]["bigqueryExportSettings"]
    assert logging["project"] == "tgt-proj-456"
    assert "projects/999888777666/" in json.dumps(env["tools"])


def test_target_readiness_report_flags_missing_and_ready_resources(
    tmp_path: Path,
) -> None:
    pull = pull_world(tmp_path)
    ready = audit_target_readiness(
        source_app_dir=pull.app,
        target_project_id=PROJECT,
        target_project_number=NUMBER,
        reader=ApiReader(pull.cloud),
    )
    assert ready["ready"] is True
    assert ready["summary"]["missing"] == 0
    assert ready["summary"]["misconfigured"] == 0
    text_ready = format_readiness_report(ready)
    assert "[READY]" in text_ready
    assert "all attached resources Ready" in text_ready

    empty_cloud = FakeCloud({})
    missing = audit_target_readiness(
        source_app_dir=pull.app,
        target_project_id="empty-target-123",
        target_project_number="999888777666",
        reader=ApiReader(empty_cloud),
    )
    assert missing["ready"] is False
    assert missing["summary"]["missing"] > 0
    text_missing = format_readiness_report(missing)
    assert "[MISSING]" in text_missing
    assert "passport/bigquery/orders_ds/schema.sql" in text_missing
    assert "passport/bigquery/orders_ds/seed.sql" in text_missing

    # Gap A (api_disabled -> MISSING), Gap B (invoker-iam-disabled -> MISCONFIGURED),
    # Gap C (missing resource-level IAM binding -> MISCONFIGURED), Gap D (## Target project setup)
    assert "## Target project setup" in pull.text("PLACEHOLDERS.md")
    miscfg_routes = default_routes()
    miscfg_routes[("GET", f"{BQ}/orders_ds")] = (
        200,
        {"kind": "bigquery#dataset", "access": []},
    )
    fn_svc_no_flag = function_service()
    fn_svc_no_flag["metadata"]["annotations"].pop(
        "run.googleapis.com/invoker-iam-disabled", None
    )
    miscfg_routes[("GET", f"{RUN_KN}/loyalty-api")] = (200, fn_svc_no_flag)
    miscfg_routes[("GET", DS)] = api_disabled("discoveryengine.googleapis.com")
    miscfg = audit_target_readiness(
        source_app_dir=pull.app,
        target_project_id=PROJECT,
        target_project_number=NUMBER,
        reader=ApiReader(FakeCloud(miscfg_routes)),
    )
    assert miscfg["ready"] is False
    text_miscfg = format_readiness_report(miscfg)
    assert (
        "gcloud services enable discoveryengine.googleapis.com" in text_miscfg
    )
    assert "--no-invoker-iam-check" in text_miscfg
    assert "GRANT `roles/bigquery.dataViewer` ON SCHEMA" in text_miscfg


def test_format_readiness_report_matches_pull_style_and_edge_cases() -> None:
    assert (
        format_readiness_report({"checked": False, "ready": True, "checks": []})
        == ""
    )
    assert (
        format_readiness_report({"checked": True, "ready": True, "checks": []})
        == ""
    )

    report = {
        "checked": True,
        "target_project_id": "demo-tgt",
        "ready": False,
        "summary": {
            "ready": 1,
            "missing": 1,
            "misconfigured": 1,
            "not_checked": 1,
        },
        "checks": [
            {
                "status": "READY",
                "kind": "storage.bucket",
                "resource": "Cloud Storage bucket `demo-tgt-kb`",
                "detail": "bucket present",
                "remediation": "should not print",
            },
            {
                "status": "MISSING",
                "kind": "bigquery.dataset",
                "resource": "BigQuery dataset `orders_ds`",
                "detail": "dataset `demo-tgt.orders_ds` does not exist",
                "remediation": "Run: passport/bigquery/orders_ds/schema.sql",
            },
            {
                "status": "MISCONFIGURED",
                "kind": "project.iam",
                "resource": "IAM role `roles/bigquery.jobUser` for `serviceAccount:sa@demo-tgt.iam.gserviceaccount.com`",
                "detail": "missing on project `demo-tgt`",
                "remediation": "gcloud projects add-iam-policy-binding demo-tgt ...",
            },
            {
                "status": "NOT_CHECKED",
                "kind": "custom.widget",
                "resource": "Widget `w1`",
                "detail": "HTTP 503",
                "remediation": "should not print",
            },
        ],
        "latency_ms": {"total_readiness_audit_ms": 1250.0},
        "timings_by_kind_ms": {
            "readiness.bigquery": 800.0,
            "readiness.storage": 450.0,
        },
    }
    text = format_readiness_report(report)
    assert "CXAS Passport target readiness:" in text
    assert "Target project:      demo-tgt" in text
    assert (
        "Checks total:        4 (1 ready, 1 missing, 1 misconfigured, 1 not checked)"
        in text
    )
    assert "Target Resource Readiness (4):" in text
    assert "• Cloud Storage (1 bucket)" in text
    assert "- [READY] gs://demo-tgt-kb: bucket present" in text
    assert "• BigQuery (1 dataset)" in text
    assert (
        "- [MISSING] orders_ds: dataset `demo-tgt.orders_ds` does not exist"
        in text
    )
    assert "-> Run: passport/bigquery/orders_ds/schema.sql" in text
    assert "• Project IAM (1 check)" in text
    assert (
        "- [MISCONFIGURED] roles/bigquery.jobUser for "
        "serviceAccount:sa@demo-tgt.iam.gserviceaccount.com:" in text
    )
    assert "• Custom (1 resource)" in text
    assert "should not print" not in text
    assert (
        "Readiness latency:   1.2s" in text
        or "Readiness latency:   1.3s" in text
    )
    assert "GCP reads by kind:   bigquery 800 ms, storage 450 ms" in text
    assert "cxas push --passport --project-id demo-tgt --strict" in text

    # NOT_CHECKED-only report should say "not verified", not falsely say Ready
    not_checked_only = {
        "checked": True,
        "target_project_id": "demo-tgt",
        "ready": True,
        "summary": {
            "ready": 0,
            "missing": 0,
            "misconfigured": 0,
            "not_checked": 1,
        },
        "checks": [
            {
                "status": "NOT_CHECKED",
                "kind": "bigquery.dataset",
                "resource": "BigQuery dataset `orders_ds`",
                "detail": "HTTP 403",
                "remediation": None,
            }
        ],
    }
    not_checked_text = format_readiness_report(not_checked_only)
    assert "not verified (0 ready, 1 not checked)" in not_checked_text
    assert "Target resources in demo-tgt are ready" not in not_checked_text
    assert "all attached resources Ready" not in not_checked_text


def test_audit_target_readiness_ignores_prior_reader_timings_and_non_dict_resources(
    tmp_path: Path,
) -> None:
    app_dir = tmp_path / "app"
    (app_dir / "passport").mkdir(parents=True)
    (app_dir / "passport" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "4.0",
                "resources": ["unexpected-list"],
                "identities": [],
            }
        ),
        encoding="utf-8",
    )
    reader = ApiReader(FakeCloud({}))
    reader.timings_ms["bigquery.dataset"] = 1234.5
    reader.timings_ms["readiness.bigquery"] = 500.0
    rep = audit_target_readiness(
        source_app_dir=app_dir,
        target_project_id="tgt-proj",
        reader=reader,
    )
    assert rep["checked"] is True
    assert rep["ready"] is True
    assert rep["checks"] == []
    assert rep["timings_by_kind_ms"] == {}


def test_deleting_seed_sql_does_not_block_or_fail_push(
    tmp_path: Path,
) -> None:
    pull = pull_world(tmp_path)
    seed_sql = pull.app / "passport" / "bigquery" / "orders_ds" / "seed.sql"
    assert seed_sql.is_file()
    seed_sql.unlink()
    assert not seed_sql.exists()

    staging = tmp_path / "staging"
    for rel in ("app.json", "environment.json", "agents", "tools", "toolsets"):
        src = pull.app / rel
        if src.is_dir():
            shutil.copytree(src, staging / rel)
        else:
            staging.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, staging / rel)

    report = passport_import.prepare_passport_push(
        staging_dir=staging,
        source_app_dir=pull.app,
        target_project_id=PROJECT,
        target_location="us",
        strict_gates=True,
        project_number_resolver=lambda pid: NUMBER if pid == PROJECT else None,
    )
    assert report["gates_passed"] is True
    assert report["fatal_passed"] is True
    assert report["unresolved_placeholders"] == []

    ready = audit_target_readiness(
        source_app_dir=pull.app,
        target_project_id=PROJECT,
        target_project_number=NUMBER,
        reader=ApiReader(pull.cloud),
    )
    assert ready["ready"] is True
    assert ready["summary"]["missing"] == 0

    # When target dataset is missing, remediation omits the deleted seed.sql
    missing_report = audit_target_readiness(
        source_app_dir=pull.app,
        target_project_id="empty-target-123",
        target_project_number="999888777666",
        reader=ApiReader(FakeCloud({})),
    )
    missing_text = format_readiness_report(missing_report)
    assert "passport/bigquery/orders_ds/schema.sql" in missing_text
    assert "passport/bigquery/orders_ds/seed.sql" not in missing_text


def test_audit_target_readiness_handles_vertex_ai_search_engine_distinct_from_datastore(
    tmp_path: Path,
) -> None:
    app_dir = tmp_path / "app"
    (app_dir / "passport" / "vertex_ai_search" / "engine-search-app").mkdir(
        parents=True
    )
    (
        app_dir
        / "passport"
        / "vertex_ai_search"
        / "engine-search-app"
        / "engine.json"
    ).write_text("{}", encoding="utf-8")
    (app_dir / "passport" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "4.0",
                "resources": {
                    "vertex_ai_search": [
                        {
                            "kind": "discoveryengine.engine",
                            "name": "search-app",
                            "id": "projects/${GCP_PROJECT}/locations/global/collections/default_collection/engines/search-app",
                            "folder": "passport/vertex_ai_search/engine-search-app",
                            "files": ["engine.json"],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    missing = audit_target_readiness(
        source_app_dir=app_dir,
        target_project_id="tgt-proj",
        reader=ApiReader(FakeCloud({})),
    )
    assert missing["ready"] is False
    (chk,) = missing["checks"]
    assert chk["kind"] == "discoveryengine.engine"
    assert chk["resource"] == "Vertex AI Search engine `search-app`"
    assert (
        chk["remediation"]
        == "Config: passport/vertex_ai_search/engine-search-app/engine.json"
    )
    txt = format_readiness_report(missing)
    assert "• Vertex AI Search (1 engine)" in txt
    assert (
        "- [MISSING] search-app: engine does not exist in the target project"
        in txt
    )
