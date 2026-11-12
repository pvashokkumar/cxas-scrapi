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

"""Unit tests for the export entry point of `cxas pull --passport`.

`passport.export.run_passport_export` on a Retail-shaped agent: the bundle
layout, orphan toolsets, and exports over an earlier bundle in the same folder.
The helpers it relies on are tested in test_passport_helpers.py.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import TYPE_CHECKING

import pytest
from passport_fakes import (
    SRC_NUMBER,
    SRC_PROJECT,
    snapshot,
    write,
    write_retail_agent,
)
from passport_v4_cloud import CRM, GCS, FakeCloud

from cxas_scrapi.utils.passport.export import run_passport_export
from cxas_scrapi.utils.passport.http import ApiReader
from cxas_scrapi.utils.passport.model import Scrubber
from cxas_scrapi.utils.passport.previous import remove_previous_passport
from cxas_scrapi.utils.passport.scrub import Writer

if TYPE_CHECKING:
    from pathlib import Path

APP = f"projects/{SRC_PROJECT}/locations/us/apps/00000000-0000-4000-8000-000000000002"
PROJECT_ROUTE = {
    ("GET", f"{CRM}/{SRC_PROJECT}"): (
        200,
        {"projectId": SRC_PROJECT, "projectNumber": SRC_NUMBER},
    ),
}
HOLD_BUCKET_ROUTES = {
    **PROJECT_ROUTE,
    ("GET", f"{GCS}/hold-music-audio"): (
        200,
        {"name": "hold-music-audio", "projectNumber": SRC_NUMBER},
    ),
}


def _export(root: Path, routes: dict | None = None) -> dict:
    """The export of `root`: offline, or reading `routes` of the fake cloud."""
    return run_passport_export(
        app_root=root,
        project_id=SRC_PROJECT,
        location="us",
        app_name=APP,
        live_introspect=routes is not None,
        reader=None
        if routes is None
        else ApiReader(FakeCloud(dict(routes)), sleep=lambda _s: None),
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def test_export_writes_the_metadata_layout_and_takes_no_legacy_switch(
    tmp_path: Path,
) -> None:
    root = write_retail_agent(tmp_path / "Retail")
    audio = root / "agents/order_support_agent/hold.raw"
    audio.write_bytes(b"\x00\x01audio\xff")
    report = _export(root)
    manifest = json.loads((root / "passport/manifest.json").read_text())
    assert manifest["schema_version"] == "4.0"
    assert manifest["bundle_layout"] == report["bundle_layout"] == "passport-v4"
    # Metadata only: no setup scripts anywhere in the bundle.
    assert not [p for p in root.rglob("*") if p.suffix == ".sh"]
    # Binary files of the export are left as they are.
    assert audio.read_bytes() == b"\x00\x01audio\xff"
    for retired in ({"legacy": True}, {"gcp": object()}):
        with pytest.raises(TypeError):
            run_passport_export(
                app_root=root, project_id=SRC_PROJECT, **retired
            )


# --------------------------------------------------------------------------
# Agent files: orphan toolsets, exports over an earlier bundle
# --------------------------------------------------------------------------


def test_orphan_toolsets_are_removed_and_environment_cleaned(
    tmp_path: Path,
) -> None:
    root = write_retail_agent(tmp_path / "Retail")
    write(
        root / "toolsets/old_mcp/old_mcp.json",
        {
            "displayName": "old_mcp",
            "mcpToolset": {
                "serverAddress": f"https://old-mcp-{SRC_NUMBER}.us-central1.run.app/mcp"
            },
        },
    )
    write(
        root / "environment.json",
        {
            "toolsets": {
                "old_mcp": {"mcpToolset": {"serverAddress": "x"}},
                "retail_toolbox": {"mcpToolset": {"serverAddress": "y"}},
            }
        },
    )
    report = _export(root)
    assert report["pruned_orphans"] == ["old_mcp"]
    assert not (root / "toolsets/old_mcp").exists()
    env = json.loads((root / "environment.json").read_text())
    assert set(env["toolsets"]) == {"retail_toolbox"}
    # No resource for a removed toolset.
    assert not [r for r in report["resources"] if "old-mcp" in r["id"]]


def test_pinned_secret_version_becomes_latest_and_is_recorded(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Billing"
    write(root / "app.json", {"displayName": "Billing", "rootAgent": "billing"})
    write(
        root / "agents/billing/billing.json",
        {
            "displayName": "billing",
            "toolsets": [{"toolset": "crm_api", "toolIds": ["getAccount"]}],
        },
    )
    write(
        root / "toolsets/crm_api/crm_api.json",
        {
            "displayName": "crm_api",
            "openApiToolset": {
                "apiAuthentication": {
                    "apiKeyConfig": {
                        "keyName": "x-api-key",
                        "apiKeySecretVersion": f"projects/{SRC_NUMBER}/secrets/crm-api-key/versions/3",
                    }
                }
            },
        },
    )
    # Offline: the project number comes from the secret path itself.
    report = _export(root)
    ts = json.loads((root / "toolsets/crm_api/crm_api.json").read_text())
    assert ts["openApiToolset"]["apiAuthentication"]["apiKeyConfig"][
        "apiKeySecretVersion"
    ] == ("projects/${GCP_PROJECT_NUMBER}/secrets/crm-api-key/versions/latest")
    manifest = json.loads((root / "passport/manifest.json").read_text())
    assert [
        c["file"]
        for c in manifest["portability_changes"]
        if "latest" in c["change"]
    ] == ["toolsets/crm_api/crm_api.json"]
    assert "Secret Manager (1 secret)" in report["services_discovered"]


def test_export_over_an_earlier_bundle_gives_the_same_bundle(
    tmp_path: Path,
) -> None:
    root = write_retail_agent(tmp_path / "Retail")
    _export(root, PROJECT_ROUTE)
    (root / "passport/ledger.jsonl").write_text('{"push": 1}\n')
    (root / "passport/my_notes.txt").write_text("keep me\n")
    first = snapshot(root)

    def same_as_first() -> None:
        second = snapshot(root)
        assert set(second) == set(first)
        for rel in first:
            if rel == "passport/manifest.json":
                continue  # timings differ
            assert second[rel] == first[rel], rel

    # Again over the folder it already scrubbed: identical bundle.
    assert _export(root, PROJECT_ROUTE)["gcp_introspection_errors"] == []
    same_as_first()
    # A real `cxas pull --passport` extracts the raw files over the folder first: identical too.
    write_retail_agent(root)
    _export(root, PROJECT_ROUTE)
    same_as_first()
    # The toolset is no longer used: it is pruned and its service leaves the passport.
    agent = root / "agents/order_support_agent/order_support_agent.json"
    data = json.loads(agent.read_text())
    data["toolsets"] = []
    agent.write_text(json.dumps(data))
    _export(root, PROJECT_ROUTE)
    assert not (root / "passport/cloud_run").exists()
    assert not (root / "toolsets/retail_toolbox").exists()
    assert (root / "passport/ledger.jsonl").read_text() == '{"push": 1}\n'
    assert (root / "passport/my_notes.txt").is_file()


def test_export_over_an_earlier_bundle_reports_placeholders_it_cannot_restore(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Hold"
    write(root / "app.json", {"displayName": "Hold", "rootAgent": "a"})
    write(root / "agents/a/a.json", {"displayName": "a"})
    write(
        root / "agents/a/instruction.txt",
        "Play gs://hold-music-audio/x.raw while waiting.\n",
    )
    _export(root, HOLD_BUCKET_ROUTES)
    assert (
        "gs://${GCS_BUCKET_HOLD_MUSIC_AUDIO}/x.raw"
        in (root / "agents/a/instruction.txt").read_text()
    )
    # Again over the scrubbed folder: the bucket's source name is gone, so the run says so.
    again = _export(root, HOLD_BUCKET_ROUTES)
    assert any(
        "${GCS_BUCKET_HOLD_MUSIC_AUDIO}" in e and "pull the app again" in e
        for e in again["gcp_introspection_errors"]
    )
    manifest = json.loads((root / "passport/manifest.json").read_text())
    # The placeholder is still listed, so `cxas push` asks for it instead of pushing a broken URI.
    assert (
        manifest["placeholders"]["GCS_BUCKET_HOLD_MUSIC_AUDIO"][
            "required_for_push"
        ]
        is True
    )


def test_export_preserves_toolset_referenced_via_toolset_tool_wrapper(
    tmp_path: Path,
) -> None:
    root = tmp_path / "WrapperAgent"
    write(root / "app.json", {"displayName": "WrapperAgent", "rootAgent": "r"})
    write(
        root / "agents/r/r.json",
        {"displayName": "r", "tools": ["search_orders"]},
    )
    write(
        root / "tools/search_orders/search_orders.json",
        {
            "displayName": "search_orders",
            "toolsetTool": {
                "toolset": f"projects/{SRC_PROJECT}/locations/us/apps/a1/toolsets/orders_mcp",
                "toolId": "find_order",
            },
        },
    )
    write(
        root / "toolsets/orders_mcp/orders_mcp.json",
        {
            "displayName": "orders_mcp",
            "mcpToolset": {
                "serverAddress": f"https://orders-mcp-{SRC_NUMBER}.us-central1.run.app/mcp"
            },
        },
    )
    report = _export(root)
    assert report["pruned_orphans"] == []
    assert (root / "toolsets/orders_mcp/orders_mcp.json").is_file()
    assert report["active_toolsets"] == ["orders_mcp"]


def test_remove_previous_passport_blocks_path_traversal_outside_passport_dir(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "secret_outside.txt"
    outside.write_text("do-not-delete", encoding="utf-8")
    app = tmp_path / "App"
    write(app / "app.json", {"displayName": "App"})
    write(
        app / "passport/manifest.json",
        {
            "files": [
                {"path": "passport/../app.json"},
                {"path": "passport/../../secret_outside.txt"},
                {"path": "passport/bigquery/ds/README.md"},
            ]
        },
    )
    write(app / "passport/bigquery/ds/README.md", "# ds\n")
    removed = remove_previous_passport(app)
    assert outside.is_file()
    assert (app / "app.json").is_file()
    assert not (app / "passport/bigquery/ds/README.md").exists()
    assert "passport/../app.json" not in removed
    assert "passport/../../secret_outside.txt" not in removed


def test_export_blocks_zip_slip_gcs_traversal_reserved_collisions_and_symlinks(
    tmp_path: Path,
) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../../zip_outside.py", "pwned = True\n")
        zf.writestr("function.json", '{"overwritten": true}\n')
        zf.writestr("README.md", "# fake readme\n")
        zf.writestr("main.py", f'PROJ = "{SRC_PROJECT}"\n')

    outside_target = tmp_path / "external_secret.py"
    outside_target.write_text(f'RAW = "{SRC_PROJECT}"\n', encoding="utf-8")

    app = tmp_path / "sub" / "SafeApp"
    write(app / "app.json", {"displayName": "SafeApp", "rootAgent": "r"})
    write(
        app / "agents/r/r.json",
        {"displayName": "r", "instruction": "agents/r/instruction.txt"},
    )
    write(
        app / "agents/r/instruction.txt",
        f"Call https://us-central1-{SRC_PROJECT}.cloudfunctions.net/myfn and gs://{SRC_PROJECT}-kb/docs/\n",
    )
    (app / "tools/t").mkdir(parents=True)
    (app / "tools/t/link.py").symlink_to(outside_target)

    class _TraversalReader:
        def __init__(self) -> None:
            self.quota_project: str | None = None
            self.timings_ms: dict[str, float] = {}
            self.calls: list[tuple[str, str, int | None]] = []

        def get(self, url: str, *, area: str) -> dict:
            if "cloudresourcemanager" in url:
                return {"projectNumber": SRC_NUMBER}
            if "cloudfunctions.googleapis.com/v2/" in url:
                return {
                    "name": f"projects/{SRC_PROJECT}/locations/us-central1/functions/myfn",
                    "buildConfig": {
                        "runtime": "python312",
                        "dockerRepository": "gcr.io/short-repo",
                        "source": {
                            "storageSource": {
                                "bucket": "fn-src",
                                "object": "src.zip",
                            }
                        },
                    },
                }
            if url.endswith(f"/storage/v1/b/{SRC_PROJECT}-kb"):
                return {
                    "name": f"{SRC_PROJECT}-kb",
                    "projectNumber": SRC_NUMBER,
                }
            if f"/storage/v1/b/{SRC_PROJECT}-kb/o" in url:
                return {
                    "items": [
                        {
                            "name": "../../../../../gcs_outside.txt",
                            "size": "5",
                            "contentType": "text/plain",
                        },
                        {
                            "name": "docs/ok.md",
                            "size": "10",
                            "contentType": "text/markdown",
                        },
                    ]
                }
            return {}

        def get_iam_policy(
            self, url: str, *, area: str, post: bool = False
        ) -> dict:
            return {"bindings": []}

        def get_bytes(self, url: str, *, area: str) -> bytes:
            return buf.getvalue() if "fn-src" in url else b"# Guide\n"

    run_passport_export(app, project_id=SRC_PROJECT, reader=_TraversalReader())

    # Nothing escaped app/passport/ or app/, and external symlink target stayed untouched
    assert not (tmp_path / "zip_outside.py").exists()
    assert not (tmp_path / "sub/zip_outside.py").exists()
    assert not (tmp_path / "gcs_outside.txt").exists()
    assert not (tmp_path / "sub/gcs_outside.txt").exists()
    assert (
        outside_target.read_text(encoding="utf-8") == f'RAW = "{SRC_PROJECT}"\n'
    )

    # Sanitized function.json was NOT overwritten by the zip's function.json
    fn_cfg = json.loads(
        (app / "passport/cloud_functions/myfn/function.json").read_text()
    )
    assert "overwritten" not in fn_cfg
    assert fn_cfg["buildConfig"]["runtime"] == "python312"
    assert (
        'PROJ = "${GCP_PROJECT}"'
        in (app / "passport/cloud_functions/myfn/main.py").read_text()
    )
    assert (app / "passport/cloud_storage/kb/files/docs/ok.md").is_file()

    # Writer.text defense-in-depth refuses traversal and non-passport paths
    writer = Writer(app, Scrubber(SRC_PROJECT, SRC_NUMBER))
    for bad in ("passport/../../escape.txt", "outside.txt", "/abs/escape.txt"):
        with pytest.raises(ValueError, match="passport"):
            writer.text(bad, "x", "bad")
