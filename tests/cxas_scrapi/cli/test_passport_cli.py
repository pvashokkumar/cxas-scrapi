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

"""Unit tests for CXAS Passport CLI flags and end-to-end pull/push wiring."""

import io
import json
import shutil
import sys
import types
import typing
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from cxas_scrapi.cli import app as cli_app
from cxas_scrapi.cli import main as main_cli
from cxas_scrapi.cli.main import get_parser
from cxas_scrapi.utils.passport import push as passport_push

TARGET_APP = "projects/tgt-proj/locations/us/apps/scratch"


def _mock_import(mock_apps_client: typing.Any, name: str = TARGET_APP) -> None:
    lro = mock.MagicMock()
    imported = mock.MagicMock()
    imported.name = name
    lro.result.return_value = imported
    mock_apps_client.import_app.return_value = lro


def _uploaded_zip(mock_apps_client: typing.Any) -> dict[str, str]:
    mock_apps_client.import_app.assert_called_once()
    raw = mock_apps_client.import_app.call_args.kwargs["app_content"]
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        return {
            n: zf.read(n).decode("utf-8")
            for n in zf.namelist()
            if not n.endswith("/")
        }


def _push(argv_tail: list[str]) -> None:
    with mock.patch.object(sys, "argv", ["cxas", "push", *argv_tail]):
        main_cli.main()


@pytest.fixture
def mock_apps_client() -> typing.Any:
    with mock.patch(
        "cxas_scrapi.cli.app.Apps", autospec=True
    ) as mock_apps_class:
        mock_instance = mock_apps_class.return_value
        yield mock_instance


@pytest.fixture
def mock_passport_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> types.SimpleNamespace:
    """Patch passport.export and passport.push entry points for isolated CLI tests."""
    mock_run_export = mock.MagicMock(
        return_value={
            "pruned_orphans": ["C360_mcp", "Repair_poc"],
            "parameterized_files": ["app.json", "toolsets/mcp/mcp.json"],
        }
    )
    mock_prepare_push = mock.MagicMock(
        return_value={
            "gates_passed": True,
            "stamped_files_count": 3,
        }
    )
    mock_post_push = mock.MagicMock(
        return_value={
            "logged": True,
        }
    )
    mock_verify_pushed = mock.MagicMock(
        return_value={
            "checked": True,
            "ok": True,
            "problems": [],
            "warnings": [],
        }
    )

    monkeypatch.setattr(
        "cxas_scrapi.utils.passport.export.run_passport_export",
        mock_run_export,
    )
    monkeypatch.setattr(
        "cxas_scrapi.utils.passport.push.prepare_passport_push",
        mock_prepare_push,
    )
    monkeypatch.setattr(
        "cxas_scrapi.utils.passport.push.post_passport_push",
        mock_post_push,
    )
    monkeypatch.setattr(
        "cxas_scrapi.utils.passport.push.verify_pushed_app",
        mock_verify_pushed,
    )

    return types.SimpleNamespace(
        run_passport_export=mock_run_export,
        prepare_passport_push=mock_prepare_push,
        post_passport_push=mock_post_push,
        verify_pushed_app=mock_verify_pushed,
    )


def test_parser_pull_passport_flags() -> None:
    """Verify parser_pull registers --passport and --no-live-introspect and rejects retired aliases."""
    parser = get_parser()
    args = parser.parse_args(
        [
            "pull",
            "my-app",
            "--target-dir",
            "/tmp/exported",
            "--passport",
            "--no-live-introspect",
            "--project-id",
            "source-project-123",
            "--location",
            "us",
        ]
    )
    assert args.command == "pull"
    assert args.app == "my-app"
    assert args.target_dir == "/tmp/exported"
    assert args.passport is True
    assert args.no_live_introspect is True
    assert args.project_id == "source-project-123"
    assert args.location == "us"

    for retired_argv in (
        ["pull", "--passport"],
        ["pull", "--app-id", "app-123", "--passport"],
        ["pull", "--name", "My App", "--passport"],
        ["pull", "my-app", "--local-path", "/tmp/out", "--passport"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(retired_argv)
        assert excinfo.value.code == 2


def test_parser_push_passport_flags() -> None:
    """Verify parser_push registers all --passport stamping and gate flags and rejects --dataset."""
    parser = get_parser()
    args = parser.parse_args(
        [
            "push",
            "--app-dir",
            "/tmp/agent",
            "--to",
            "target-app",
            "--passport",
            "--toolbox-url",
            "https://mcp-uat.example.com/mcp",
            "--moh-uri",
            "gs://uat-audio/moh.wav",
            "--gcs-bucket",
            "uat-eval-bucket",
            "--skip-passport-gates",
            "--project_id",
            "acme-uat-999",
            "--location",
            "us",
        ]
    )
    assert args.command == "push"
    assert args.app_dir == "/tmp/agent"
    assert args.to == "target-app"
    assert args.passport is True
    assert args.toolbox_url == "https://mcp-uat.example.com/mcp"
    assert args.moh_uri == "gs://uat-audio/moh.wav"
    assert args.gcs_bucket == "uat-eval-bucket"
    assert args.skip_passport_gates is True
    assert args.project_id == "acme-uat-999"
    assert args.location == "us"

    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["push", "--passport", "--dataset", "acme_uat"])
    assert excinfo.value.code == 2


def test_cli_pull_passport_direct_root(
    mock_apps_client: typing.Any,
    mock_passport_modules: types.SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify cxas pull <app> --passport --no-live-introspect end-to-end."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(
            "app.json",
            json.dumps({"displayName": "Demo App", "rootAgent": "root_agent"}),
        )
        zf.writestr(
            "agents/root_agent/root_agent.json",
            json.dumps({"displayName": "root_agent"}),
        )

    mock_lro = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.app_content = zip_buf.getvalue()
    mock_lro.result.return_value = mock_resp
    mock_apps_client.export_app.return_value = mock_lro

    target_dir = tmp_path / "pulled_direct"
    argv = [
        "cxas",
        "pull",
        "projects/src-proj/locations/us/apps/app-123",
        "--target-dir",
        str(target_dir),
        "--passport",
        "--no-live-introspect",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    mock_apps_client.export_app.assert_called_once_with(
        app_name="projects/src-proj/locations/us/apps/app-123",
        app_version=None,
    )
    mock_passport_modules.run_passport_export.assert_called_once_with(
        app_root=str(target_dir),
        project_id="src-proj",
        location="us",
        app_name="projects/src-proj/locations/us/apps/app-123",
        apps_client=mock_apps_client,
        live_introspect=False,
    )
    out = capsys.readouterr().out
    assert "CXAS Passport bundle exported:" in out
    assert "C360_mcp, Repair_poc" in out
    assert f"Placeholder guide:   {target_dir}/PLACEHOLDERS.md" in out
    assert f"Passport folder:     {target_dir}/passport/" in out
    assert "Services discovered: none" in out


def test_cli_pull_passport_nested_top_dir(
    mock_apps_client: typing.Any,
    mock_passport_modules: types.SimpleNamespace,
    tmp_path: Path,
) -> None:
    """Verify cxas pull --passport resolves nested top-level folder in export zip."""
    mock_app = mock.MagicMock()
    mock_app.name = "projects/src-proj/locations/global/apps/app-456"
    mock_app.display_name = "Acme IDR Demo"
    mock_apps_client.get_app_by_display_name.return_value = mock_app

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(
            "Acme_IDR_Demo/app.json",
            json.dumps({"displayName": "Acme IDR Demo", "rootAgent": "root"}),
        )
        zf.writestr(
            "Acme_IDR_Demo/agents/root/root.json",
            json.dumps({"displayName": "root"}),
        )

    mock_lro = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.app_content = zip_buf.getvalue()
    mock_lro.result.return_value = mock_resp
    mock_apps_client.export_app.return_value = mock_lro

    target_dir = tmp_path / "pulled_nested"
    argv = [
        "cxas",
        "pull",
        "Acme IDR Demo",
        "--target-dir",
        str(target_dir),
        "--project-id",
        "src-proj",
        "--location",
        "global",
        "--passport",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    expected_root = str(target_dir / "Acme_IDR_Demo")
    mock_passport_modules.run_passport_export.assert_called_once_with(
        app_root=expected_root,
        project_id="src-proj",
        location="global",
        app_name="projects/src-proj/locations/global/apps/app-456",
        apps_client=mock_apps_client,
        live_introspect=True,
    )


def test_cli_push_passport_end_to_end(
    mock_apps_client: typing.Any,
    mock_passport_modules: types.SimpleNamespace,
    tmp_path: Path,
) -> None:
    """Verify cxas push --passport stamps staging_dir before zipping and logs post-push."""
    app_dir = tmp_path / "sample_agent"
    (app_dir / "agents" / "root_agent").mkdir(parents=True)
    (app_dir / "passport").mkdir(parents=True)

    (app_dir / "app.json").write_text(
        json.dumps({"displayName": "Source App", "rootAgent": "root_agent"})
    )
    (app_dir / "agents" / "root_agent" / "root_agent.json").write_text(
        json.dumps({"displayName": "root_agent"})
    )
    (app_dir / "passport" / "manifest.json").write_text(
        json.dumps({"schema_version": "4.0", "bundle_layout": "passport-v4"})
    )
    (app_dir / "PLACEHOLDERS.md").write_text("# Placeholders\n")

    def fake_prepare_push(**kwargs: typing.Any) -> dict[str, typing.Any]:
        staging = Path(kwargs["staging_dir"])
        app_json_path = staging / "app.json"
        data = json.loads(app_json_path.read_text())
        data["stampedProject"] = kwargs["target_project_id"]
        data["stampedToolbox"] = kwargs["target_toolbox_url"]
        app_json_path.write_text(json.dumps(data))
        return {"gates_passed": True, "stamped_files_count": 2}

    mock_passport_modules.prepare_passport_push.side_effect = fake_prepare_push

    mock_lro = mock.MagicMock()
    mock_imported = mock.MagicMock()
    mock_imported.name = "projects/acme-uat-999/locations/us/apps/app-789"
    mock_lro.result.return_value = mock_imported
    mock_apps_client.import_app.return_value = mock_lro

    argv = [
        "cxas",
        "push",
        "--app-dir",
        str(app_dir),
        "--to",
        "projects/acme-uat-999/locations/us/apps/app-789",
        "--passport",
        "--toolbox-url",
        "https://mcp-uat.example.com/mcp",
        "--moh-uri",
        "gs://uat-bkt/moh.wav",
        "--gcs-bucket",
        "uat-eval-bkt",
        "--overwrite",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    mock_passport_modules.prepare_passport_push.assert_called_once()
    prep_kwargs = mock_passport_modules.prepare_passport_push.call_args.kwargs
    assert prep_kwargs["source_app_dir"] == str(app_dir)
    assert prep_kwargs["target_project_id"] == "acme-uat-999"
    assert prep_kwargs["target_location"] == "us"
    assert "target_dataset" not in prep_kwargs
    assert (
        prep_kwargs["target_toolbox_url"] == "https://mcp-uat.example.com/mcp"
    )
    assert prep_kwargs["target_moh_uri"] == "gs://uat-bkt/moh.wav"
    assert prep_kwargs["target_gcs_bucket"] == "uat-eval-bkt"
    assert prep_kwargs["strict_gates"] is True

    mock_apps_client.import_app.assert_called_once()
    upload_kwargs = mock_apps_client.import_app.call_args.kwargs
    assert upload_kwargs["conflict_strategy"] == "OVERWRITE"
    with zipfile.ZipFile(io.BytesIO(upload_kwargs["app_content"])) as zf:
        names = zf.namelist()
        assert "agent/app.json" in names
        assert not any(n.startswith("agent/passport") for n in names)
        assert not any("PLACEHOLDERS" in n for n in names)
        stamped_app = json.loads(zf.read("agent/app.json").decode("utf-8"))
        assert stamped_app["stampedProject"] == "acme-uat-999"
        assert (
            stamped_app["stampedToolbox"] == "https://mcp-uat.example.com/mcp"
        )

    mock_passport_modules.post_passport_push.assert_called_once_with(
        source_app_dir=str(app_dir),
        app_name="projects/acme-uat-999/locations/us/apps/app-789",
        created_version_name=None,
        target_project_id="acme-uat-999",
        target_location="us",
        stamp_report={"gates_passed": True, "stamped_files_count": 2},
    )


def test_cli_push_passport_gate_failure_aborts(
    mock_apps_client: typing.Any,
    mock_passport_modules: types.SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify cxas push --passport aborts before upload when invariant gates fail."""
    (tmp_path / "app.json").write_text(json.dumps({"displayName": "Bad App"}))
    mock_passport_modules.prepare_passport_push.side_effect = ValueError(
        "Gate 3 failed: missing tool binding"
    )

    argv = [
        "cxas",
        "push",
        "--app-dir",
        str(tmp_path),
        "--project-id",
        "uat-proj",
        "--location",
        "us",
        "--passport",
    ]
    with (
        mock.patch.object(sys, "argv", argv),
        pytest.raises(SystemExit) as excinfo,
    ):
        main_cli.main()

    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Gate 3 failed: missing tool binding" in out
    mock_apps_client.import_app.assert_not_called()
    mock_apps_client.import_as_new_app.assert_not_called()
    mock_passport_modules.post_passport_push.assert_not_called()


@mock.patch("cxas_scrapi.cli.app.Versions", autospec=True)
def test_cli_push_passport_skip_gates_and_create_version(
    mock_versions_cls: typing.Any,
    mock_apps_client: typing.Any,
    mock_passport_modules: types.SimpleNamespace,
    tmp_path: Path,
) -> None:
    """Verify --skip-passport-gates sets strict_gates=False and forwards created_version_name."""
    mock_apps_client.creds = mock.MagicMock()
    (tmp_path / "app.json").write_text(json.dumps({"displayName": "New App"}))

    mock_lro = mock.MagicMock()
    mock_imported = mock.MagicMock()
    mock_imported.name = "projects/uat-proj/locations/us/apps/new-app"
    mock_lro.result.return_value = mock_imported
    mock_apps_client.import_as_new_app.return_value = mock_lro

    mock_version = mock.MagicMock()
    mock_version.name = (
        "projects/uat-proj/locations/us/apps/new-app/versions/v2"
    )
    mock_versions_cls.return_value.create_version.return_value = mock_version

    argv = [
        "cxas",
        "push",
        "--app-dir",
        str(tmp_path),
        "--project-id",
        "uat-proj",
        "--location",
        "us",
        "--display-name",
        "Custom UAT App",
        "--passport",
        "--skip-passport-gates",
        "--create-version",
        "--version-name",
        "v2.0.0",
    ]
    with mock.patch.object(sys, "argv", argv):
        cli_app.app_push(get_parser().parse_args(argv[1:]))

    prep_kwargs = mock_passport_modules.prepare_passport_push.call_args.kwargs
    assert prep_kwargs["strict_gates"] is False
    assert prep_kwargs["preserve_display_name"] == "Custom UAT App"

    mock_passport_modules.post_passport_push.assert_called_once_with(
        source_app_dir=str(tmp_path),
        app_name="projects/uat-proj/locations/us/apps/new-app",
        created_version_name="projects/uat-proj/locations/us/apps/new-app/versions/v2",
        target_project_id="uat-proj",
        target_location="us",
        stamp_report={"gates_passed": True, "stamped_files_count": 3},
    )


def test_cli_pull_and_push_passport_real_engines_roundtrip(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End-to-end CLI roundtrip using the real passport.export and passport.push engines."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(
            "Sample_Agent/app.json",
            json.dumps(
                {
                    "displayName": "Sample Agent",
                    "rootAgent": "root_agent",
                    "loggingSettings": {
                        "bigqueryExportSettings": {"project": "source-proj-111"}
                    },
                }
            ),
        )
        zf.writestr(
            "Sample_Agent/agents/root_agent/root_agent.json",
            json.dumps(
                {
                    "displayName": "root_agent",
                    "tools": ["lookup_order"],
                    "toolsets": [
                        {
                            "toolset": "mcp_main",
                            "toolIds": ["query_orders"],
                        }
                    ],
                }
            ),
        )
        zf.writestr(
            "Sample_Agent/agents/root_agent/instruction.txt",
            "Use {@TOOL: lookup_order} to look up orders.\n",
        )
        zf.writestr(
            "Sample_Agent/tools/lookup_order/lookup_order.json",
            json.dumps(
                {
                    "displayName": "lookup_order",
                    "pythonFunction": {
                        "name": "lookup_order",
                        "pythonCode": "tools/lookup_order/python_function/python_code.py",
                    },
                }
            ),
        )
        zf.writestr(
            "Sample_Agent/tools/lookup_order/python_function/python_code.py",
            '_DS = "source-proj-111.billing_ds"\ndef lookup_order() -> dict:\n    return {"ds": _DS}\n',
        )
        zf.writestr(
            "Sample_Agent/toolsets/mcp_main/mcp_main.json",
            json.dumps(
                {
                    "displayName": "mcp_main",
                    "mcpToolset": {
                        "serverAddress": "https://mcp-dev.source.run.app/mcp"
                    },
                }
            ),
        )
        zf.writestr(
            "Sample_Agent/toolsets/orphan_mcp/orphan_mcp.json",
            json.dumps(
                {
                    "displayName": "orphan_mcp",
                    "mcpToolset": {
                        "serverAddress": "https://orphan.source.run.app/mcp"
                    },
                }
            ),
        )

    mock_lro = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.app_content = zip_buf.getvalue()
    mock_lro.result.return_value = mock_resp
    mock_apps_client.export_app.return_value = mock_lro

    pull_target = tmp_path / "workspace"
    pull_argv = [
        "cxas",
        "pull",
        "projects/source-proj-111/locations/us/apps/app-src",
        "--target-dir",
        str(pull_target),
        "--passport",
        "--no-live-introspect",
    ]
    with mock.patch.object(sys, "argv", pull_argv):
        main_cli.main()

    extracted_root = pull_target / "Sample_Agent"
    assert (extracted_root / "passport" / "manifest.json").is_file()
    assert (extracted_root / "PLACEHOLDERS.md").is_file()
    assert {p.name for p in extracted_root.iterdir()} == {
        "app.json",
        "agents",
        "tools",
        "toolsets",
        "PLACEHOLDERS.md",
        "passport",
    }
    bq_dir = extracted_root / "passport" / "bigquery" / "billing_ds"
    assert (bq_dir / "README.md").is_file()
    assert not (bq_dir / "schema.sql").exists()
    assert not list((extracted_root / "passport").rglob("*.sh"))
    assert not (extracted_root / "toolsets" / "orphan_mcp").exists()

    mock_import_lro = mock.MagicMock()
    mock_imported_app = mock.MagicMock()
    mock_imported_app.name = "projects/target-uat-999/locations/us/apps/app-uat"
    mock_import_lro.result.return_value = mock_imported_app
    mock_apps_client.import_app.return_value = mock_import_lro

    push_argv = [
        "cxas",
        "push",
        "--app-dir",
        str(extracted_root),
        "--to",
        "projects/target-uat-999/locations/us/apps/app-uat",
        "--project_id",
        "target-uat-999",
        "--location",
        "us",
        "--passport",
        "--toolbox-url",
        "https://mcp-uat.target.run.app/mcp",
        "--overwrite",
    ]
    with mock.patch.object(sys, "argv", push_argv):
        main_cli.main()

    mock_apps_client.import_app.assert_called_once()
    uploaded_bytes = mock_apps_client.import_app.call_args.kwargs["app_content"]
    with zipfile.ZipFile(io.BytesIO(uploaded_bytes)) as zf:
        members = zf.namelist()
        assert not any(
            m.startswith("agent/passport") or "PLACEHOLDERS" in m
            for m in members
        )
        py_code = zf.read(
            "agent/tools/lookup_order/python_function/python_code.py"
        ).decode("utf-8")
        assert '_DS = "target-uat-999.billing_ds"' in py_code
        mcp_cfg = json.loads(
            zf.read("agent/toolsets/mcp_main/mcp_main.json").decode("utf-8")
        )
        assert (
            mcp_cfg["mcpToolset"]["serverAddress"]
            == "https://mcp-uat.target.run.app/mcp"
        )
        assert not any(
            "${" in zf.read(m).decode("utf-8")
            for m in members
            if not m.endswith("/")
        )

    assert (extracted_root / "passport" / "ledger.jsonl").is_file()
    out = capsys.readouterr().out
    assert "CXAS Passport bundle exported:" in out
    folder_line = next(
        ln
        for ln in out.splitlines()
        if ln.strip().startswith("Passport folder:")
    )
    assert f"{extracted_root}/passport/" in folder_line
    assert "billing_ds" in out.lower() or "bigquery" in out.lower()
    assert (
        f"Passport manifest: {(extracted_root / 'passport' / 'manifest.json').resolve()}"
        in out
    )


@pytest.mark.parametrize("extra_flags", [(), ("--passport",)])
def test_cli_pull_missing_app_exits_never_auto_creates(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra_flags: tuple[str, ...],
) -> None:
    """Verify cxas pull 'Missing Agent' (with or without --passport) exits 1 and never creates an app."""
    mock_apps_client.get_app_by_display_name.return_value = None
    mock_apps_client.list_apps.return_value = []

    argv = [
        "cxas",
        "pull",
        "Missing Agent",
        "--project-id",
        "p",
        "--location",
        "us",
        "--target-dir",
        str(tmp_path),
        *extra_flags,
    ]
    with (
        mock.patch.object(sys, "argv", argv),
        pytest.raises(SystemExit) as excinfo,
    ):
        main_cli.main()

    assert excinfo.value.code == 1
    mock_apps_client.create_app.assert_not_called()
    assert "App 'Missing Agent' not found." in capsys.readouterr().out


def test_cli_pull_passport_bare_positional_app_id_matches_existing_app(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify cxas pull <bare_uuid> matches existing app in list_apps()."""
    mock_apps_client.get_app_by_display_name.return_value = None
    existing_app = mock.MagicMock()
    existing_app.name = (
        "projects/example-source-proj/locations/us/apps/"
        "00000000-0000-4000-8000-000000000001"
    )
    existing_app.display_name = "My New Agent"
    mock_apps_client.list_apps.return_value = [existing_app]
    shell_zip_buf = io.BytesIO()
    with zipfile.ZipFile(shell_zip_buf, "w") as zf:
        zf.writestr(
            "My_New_Agent/app.json",
            json.dumps({"displayName": "My New Agent"}),
        )
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(
        app_content=shell_zip_buf.getvalue()
    )
    mock_apps_client.export_app.return_value = lro

    out_dir = tmp_path / "bare_uuid_pull"
    argv = [
        "cxas",
        "pull",
        "00000000-0000-4000-8000-000000000001",
        "--project-id",
        "example-source-proj",
        "--location",
        "us",
        "--target-dir",
        str(out_dir),
        "--passport",
        "--no-live-introspect",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    mock_apps_client.create_app.assert_not_called()
    mock_apps_client.export_app.assert_called_once_with(
        app_name=(
            "projects/example-source-proj/locations/us/apps/"
            "00000000-0000-4000-8000-000000000001"
        ),
        app_version=None,
    )
    app_json = json.loads((out_dir / "My_New_Agent" / "app.json").read_text())
    assert app_json == {"displayName": "My New Agent"}
    assert "CXAS Passport bundle exported:" in capsys.readouterr().out


def test_cli_push_passport_resolves_nested_new_layout_app_dir(
    mock_apps_client: typing.Any,
    tmp_path: Path,
) -> None:
    """--app-dir <parent> finds <parent>/<App>/passport/manifest.json; ledger lands in passport/."""
    nested_root = tmp_path / "My_New_Agent"
    (nested_root / "agents" / "Starter_Agent").mkdir(parents=True)
    (nested_root / "app.json").write_text(
        json.dumps(
            {"displayName": "My New Agent", "rootAgent": "Starter_Agent"}
        )
    )
    (
        nested_root / "agents" / "Starter_Agent" / "Starter_Agent.json"
    ).write_text(
        json.dumps(
            {
                "displayName": "Starter_Agent",
                "instruction": "agents/Starter_Agent/instruction.txt",
                "tools": ["end_session"],
            }
        )
    )
    (nested_root / "agents" / "Starter_Agent" / "instruction.txt").write_text(
        "Use {@TOOL: end_session} when done.\n"
    )
    (nested_root / "passport").mkdir()
    (nested_root / "passport" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "4.0",
                "bundle_layout": "passport-v4",
                "app": {"display_name": "My New Agent"},
            }
        )
    )
    (nested_root / "PLACEHOLDERS.md").write_text("# My New Agent\n")

    mock_lro = mock.MagicMock()
    mock_imported = mock.MagicMock()
    mock_imported.name = "projects/tgt-proj/locations/us/apps/scratch"
    mock_lro.result.return_value = mock_imported
    mock_apps_client.import_app.return_value = mock_lro

    argv = [
        "cxas",
        "push",
        "--app-dir",
        str(tmp_path),
        "--to",
        "projects/tgt-proj/locations/us/apps/scratch",
        "--passport",
        "--overwrite",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    mock_apps_client.import_app.assert_called_once()
    assert (nested_root / "passport" / "ledger.jsonl").is_file()
    assert not (tmp_path / "passport").exists()

    # Also works when nested child app directory has no pre-existing passport/manifest.json
    plain_parent = tmp_path / "plain_ws"
    plain_nested = plain_parent / "Plain_Child"
    shutil.copytree(nested_root, plain_nested)
    shutil.rmtree(plain_nested / "passport")
    (plain_nested / "PLACEHOLDERS.md").unlink()
    mock_apps_client.import_app.reset_mock()
    with mock.patch.object(
        sys,
        "argv",
        [
            "cxas",
            "push",
            "--app-dir",
            str(plain_parent),
            "--to",
            "projects/tgt-proj/locations/us/apps/scratch",
            "--passport",
            "--overwrite",
        ],
    ):
        main_cli.main()
    mock_apps_client.import_app.assert_called_once()
    assert (plain_nested / "passport" / "ledger.jsonl").is_file()
    assert not (plain_parent / "passport").exists()


def test_cli_pull_passport_existing_app_without_agents_does_not_fabricate_starter_or_init_skills(
    mock_apps_client: typing.Any,
    tmp_path: Path,
) -> None:
    """Verify pulling an existing app whose export zip has no agents/ folder does not fabricate Starter_Agent."""
    shell_zip_buf = io.BytesIO()
    with zipfile.ZipFile(shell_zip_buf, "w") as zf:
        zf.writestr(
            "My_New_Agent/app.json",
            json.dumps(
                {
                    "name": "00000000-0000-4000-8000-000000000001",
                    "displayName": "My New Agent",
                    "timeZoneSettings": {"timeZone": "America/Los_Angeles"},
                }
            ),
        )
        zf.writestr("My_New_Agent/pythonEnvFiles/pythonEnvFiles.json", "{}")

    mock_lro = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.app_content = shell_zip_buf.getvalue()
    mock_lro.result.return_value = mock_resp
    mock_apps_client.export_app.return_value = mock_lro

    target_dir = tmp_path / "test_passport_existing"
    argv = [
        "cxas",
        "pull",
        "projects/example-source-proj/locations/us/apps/00000000-0000-4000-8000-000000000001",
        "--target-dir",
        str(target_dir),
        "--passport",
        "--no-live-introspect",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()

    app_root = target_dir / "My_New_Agent"
    assert (app_root / "app.json").is_file()
    app_json = json.loads((app_root / "app.json").read_text(encoding="utf-8"))
    assert "rootAgent" not in app_json
    assert not (app_root / "agents").exists()
    assert sorted(
        str(p.relative_to(app_root)) for p in app_root.rglob("*") if p.is_file()
    ) == [
        "PLACEHOLDERS.md",
        "app.json",
        "passport/manifest.json",
        "pythonEnvFiles/pythonEnvFiles.json",
    ]
    guide = (app_root / "PLACEHOLDERS.md").read_text(encoding="utf-8")
    for word in (
        "BigQuery",
        "Cloud Run",
        "Secret Manager",
        "Cloud Storage",
        "GCS",
        "None discovered",
        "googleapis",
        "|---",
        "${",
    ):
        assert word not in guide, word
    for fp in app_root.rglob("*"):
        if fp.is_file():
            assert "example-source-proj" not in fp.read_text(encoding="utf-8")


def _blank_shell_pull(mock_apps_client: typing.Any, target_dir: Path) -> Path:
    """Real `cxas pull --passport` of a blank shell app (CES export mocked)."""
    shell_zip_buf = io.BytesIO()
    with zipfile.ZipFile(shell_zip_buf, "w") as zf:
        zf.writestr(
            "My_New_Agent/app.json",
            json.dumps(
                {
                    "name": "00000000-0000-4000-8000-000000000001",
                    "displayName": "My New Agent",
                    "timeZoneSettings": {"timeZone": "America/Los_Angeles"},
                }
            ),
        )
        zf.writestr("My_New_Agent/pythonEnvFiles/pythonEnvFiles.json", "{}")
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(
        app_content=shell_zip_buf.getvalue()
    )
    mock_apps_client.export_app.return_value = lro
    argv = [
        "cxas",
        "pull",
        "projects/example-source-proj/locations/us/apps/00000000-0000-4000-8000-000000000001",
        "--target-dir",
        str(target_dir),
        "--passport",
        "--no-live-introspect",
    ]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()
    return target_dir / "My_New_Agent"


def test_cli_pull_then_push_passport_blank_shell_gate1_roundtrip(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Gate 1 stops the push on a blank shell; --skip-passport-gates gets past it."""
    app_root = _blank_shell_pull(mock_apps_client, tmp_path / "pulled")
    assert sorted(
        str(p.relative_to(app_root)) for p in app_root.rglob("*") if p.is_file()
    ) == [
        "PLACEHOLDERS.md",
        "app.json",
        "passport/manifest.json",
        "pythonEnvFiles/pythonEnvFiles.json",
    ]
    capsys.readouterr()

    push_argv = [
        "cxas",
        "push",
        "--app-dir",
        str(app_root),
        "--to",
        "projects/tgt-proj/locations/us/apps/scratch",
        "--project-id",
        "tgt-proj",
        "--location",
        "us",
        "--passport",
    ]
    with (
        mock.patch.object(sys, "argv", push_argv),
        pytest.raises(SystemExit) as exc,
    ):
        main_cli.main()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Gate 1" in out
    assert "Missing or empty 'rootAgent' field in app.json" in out
    mock_apps_client.import_app.assert_not_called()
    mock_apps_client.import_as_new_app.assert_not_called()
    assert not (app_root / "passport" / "ledger.jsonl").exists()

    imported = mock.MagicMock()
    imported.name = "projects/tgt-proj/locations/us/apps/scratch"
    mock_apps_client.import_app.return_value = mock.MagicMock(
        result=mock.MagicMock(return_value=imported)
    )
    with mock.patch.object(sys, "argv", [*push_argv, "--skip-passport-gates"]):
        main_cli.main()
    mock_apps_client.import_app.assert_called_once()
    raw = mock_apps_client.import_app.call_args.kwargs["app_content"]
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        assert sorted(zf.namelist()) == ["agent/", "agent/app.json"]
    ledger = app_root / "passport" / "ledger.jsonl"
    assert ledger.is_file()
    assert (
        json.loads(ledger.read_text().splitlines()[-1])["gates_passed"] is False
    )


def test_cli_pull_then_push_passport_real_export_all_value_flags(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Real v4 export + push with value override flags replaces placeholders in the upload."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:

        def put(rel: str, data: typing.Any) -> None:
            zf.writestr(
                f"Sample_Agent/{rel}",
                data if isinstance(data, str) else json.dumps(data),
            )

        put(
            "app.json",
            {
                "displayName": "Sample Agent",
                "rootAgent": "root_agent",
                "loggingSettings": {
                    "bigqueryExportSettings": {"project": "source-proj-111"},
                    "evaluationAudioRecordingConfig": {
                        "gcsBucket": "gs://source-proj-111-evals"
                    },
                },
            },
        )
        put(
            "agents/root_agent/root_agent.json",
            {
                "displayName": "root_agent",
                "instruction": "agents/root_agent/instruction.txt",
                "tools": ["lookup_order"],
                "toolsets": [
                    {"toolset": "mcp_main", "toolIds": ["query_orders"]}
                ],
                "beforeToolCallbacks": [
                    {
                        "description": "MOH",
                        "pythonCode": "agents/root_agent/before_tool_callbacks/play_moh/python_code.py",
                    }
                ],
            },
        )
        put("agents/root_agent/instruction.txt", "Use {@TOOL: lookup_order}.\n")
        put(
            "agents/root_agent/before_tool_callbacks/play_moh/python_code.py",
            '_MOH_AUDIO_URI = "gs://source-proj-111-audio/hold.wav"\n\n'
            "def before_tool_callback(tool, input, callback_context):\n  return None\n",
        )
        put(
            "tools/lookup_order/lookup_order.json",
            {
                "displayName": "lookup_order",
                "pythonFunction": {
                    "name": "lookup_order",
                    "pythonCode": "tools/lookup_order/python_function/python_code.py",
                },
            },
        )
        put(
            "tools/lookup_order/python_function/python_code.py",
            '_DS = "source-proj-111.billing_ds"\n'
            "def lookup_order() -> dict:\n"
            '    q = "SELECT * FROM `source-proj-111.billing_ds.orders`"\n'
            '    return {"ds": _DS, "q": q}\n',
        )
        put(
            "toolsets/mcp_main/mcp_main.json",
            {
                "displayName": "mcp_main",
                "mcpToolset": {
                    "serverAddress": "https://mcp-toolbox-111122223333.us-central1.run.app/mcp"
                },
            },
        )
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(app_content=zip_buf.getvalue())
    mock_apps_client.export_app.return_value = lro
    with mock.patch.object(
        sys,
        "argv",
        [
            "cxas",
            "pull",
            "projects/source-proj-111/locations/us/apps/app-src",
            "--target-dir",
            str(tmp_path / "ws"),
            "--passport",
            "--no-live-introspect",
        ],
    ):
        main_cli.main()
    app_root = tmp_path / "ws" / "Sample_Agent"
    assert (app_root / "passport" / "manifest.json").is_file()
    assert (
        json.loads((app_root / "passport" / "manifest.json").read_text())[
            "schema_version"
        ]
        == "4.0"
    )
    assert "${GCP_PROJECT_NUMBER}" in (
        app_root / "toolsets" / "mcp_main" / "mcp_main.json"
    ).read_text(encoding="utf-8")
    capsys.readouterr()

    _mock_import(mock_apps_client)
    toolbox = "https://toolbox-uat-123456789012.us-central1.run.app/mcp"
    _push(
        [
            "--app-dir",
            str(app_root),
            "--to",
            TARGET_APP,
            "--project-id",
            "tgt-proj",
            "--location",
            "us",
            "--passport",
            "--toolbox-url",
            toolbox,
            "--moh-uri",
            "gs://tgt-proj-audio/custom_hold.wav",
            "--gcs-bucket",
            "gs://uat-eval-audio-bkt",
        ]
    )

    files = _uploaded_zip(mock_apps_client)
    assert not any(
        n.startswith("agent/passport") or "PLACEHOLDERS" in n for n in files
    )
    py = files["agent/tools/lookup_order/python_function/python_code.py"]
    assert '_DS = "tgt-proj.billing_ds"' in py
    assert "`tgt-proj.billing_ds.orders`" in py
    assert (
        json.loads(files["agent/toolsets/mcp_main/mcp_main.json"])[
            "mcpToolset"
        ]["serverAddress"]
        == toolbox
    )
    assert (
        '_MOH_AUDIO_URI = "gs://tgt-proj-audio/custom_hold.wav"'
        in files[
            "agent/agents/root_agent/before_tool_callbacks/play_moh/python_code.py"
        ]
    )
    app_json = json.loads(files["agent/app.json"])
    assert (
        app_json["loggingSettings"]["bigqueryExportSettings"]["project"]
        == "tgt-proj"
    )
    assert (
        app_json["loggingSettings"]["evaluationAudioRecordingConfig"][
            "gcsBucket"
        ]
        == "gs://uat-eval-audio-bkt"
    )
    leftovers = {n: c for n, c in files.items() if "${" in c}
    assert not leftovers, leftovers
    for raw_id in ("source-proj-111", "111122223333"):
        assert not any(raw_id in c for c in files.values())
    out = capsys.readouterr().out
    assert (
        f"Passport manifest: {(app_root / 'passport' / 'manifest.json').resolve()}"
        in out
    )
    assert (
        "${GCP_PROJECT_NUMBER} = 123456789012 (the --toolbox-url host)" in out
    )
    assert (app_root / "passport" / "ledger.jsonl").is_file()


def test_print_passport_export_summary_new_layout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = str(tmp_path / "Sample_Agent")
    cli_app._print_passport_export_summary(
        root,
        {
            "pruned_orphans": ["orphan_mcp"],
            "parameterized_files": [
                "app.json",
                "tools/q/python_function/python_code.py",
            ],
            "passport_dir": str(Path(root) / "passport"),
            "generated_artifacts": [
                "passport/manifest.json",
                "passport/bigquery/orders/schema.sql",
            ],
            "services_discovered": [
                "BigQuery (2 tables)",
                "Cloud Run MCP toolbox (1)",
            ],
            "latency_ms": {
                "total_passport_export_ms": 1.0,
                "total_gcp_introspection_ms": 0.0,
            },
        },
    )
    out = capsys.readouterr().out
    assert f"Placeholder guide:   {root}/PLACEHOLDERS.md" in out
    assert f"Passport folder:     {root}/passport/" in out
    assert (
        "Services discovered: BigQuery (2 tables), Cloud Run MCP toolbox (1)"
        in out
    )
    assert "Pruned orphans:      1 (orphan_mcp)" in out
    assert "Parameterized files: 2" in out


def test_print_passport_export_summary_blank_reports_none(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "My_New_Agent"
    (root / "passport").mkdir(parents=True, exist_ok=True)
    (root / "passport" / "manifest.json").write_text("{}", encoding="utf-8")
    cli_app._print_passport_export_summary(
        str(root), {"pruned_orphans": [], "parameterized_files": []}
    )
    out = capsys.readouterr().out
    assert f"Passport folder:     {root}/passport/" in out
    assert "Services discovered: none" in out


# ---- export <-> import contract (real export, CES mocked) ----

SRC_APP = "projects/source-proj-111/locations/us/apps/app-src"


def _contract_source_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:

        def put(rel: str, data: typing.Any) -> None:
            zf.writestr(
                f"Sample_Agent/{rel}",
                data if isinstance(data, str) else json.dumps(data),
            )

        put(
            "app.json",
            {
                "displayName": "Sample Agent",
                "rootAgent": "root_agent",
                "loggingSettings": {
                    "bigqueryExportSettings": {"project": "source-proj-111"}
                },
            },
        )
        put(
            "agents/root_agent/root_agent.json",
            {
                "displayName": "root_agent",
                "instruction": "agents/root_agent/instruction.txt",
                "tools": ["lookup_order"],
                "toolsets": [
                    {"toolset": "mcp_main", "toolIds": ["query_orders"]}
                ],
                "beforeToolCallbacks": [
                    {
                        "description": "MOH",
                        "pythonCode": "agents/root_agent/before_tool_callbacks/play_moh/python_code.py",
                    }
                ],
            },
        )
        put(
            "agents/root_agent/instruction.txt",
            "Use {@TOOL: lookup_order} to look up orders.\n",
        )
        put(
            "agents/root_agent/before_tool_callbacks/play_moh/python_code.py",
            '_MOH_AUDIO_URI = "gs://source-proj-111-audio/hold.wav"\n\n'
            "def before_tool_callback(tool, input, callback_context):\n  return None\n",
        )
        put(
            "tools/lookup_order/lookup_order.json",
            {
                "displayName": "lookup_order",
                "pythonFunction": {
                    "name": "lookup_order",
                    "pythonCode": "tools/lookup_order/python_function/python_code.py",
                },
            },
        )
        put(
            "tools/lookup_order/python_function/python_code.py",
            '_DS = "source-proj-111.billing_ds"\n'
            "def lookup_order() -> dict:\n"
            '    q = "SELECT * FROM `source-proj-111.billing_ds.orders`"\n'
            '    return {"ds": _DS, "q": q}\n',
        )
        put(
            "toolsets/mcp_main/mcp_main.json",
            {
                "displayName": "mcp_main",
                "mcpToolset": {
                    "serverAddress": "https://mcp-toolbox-111122223333.us-central1.run.app/mcp"
                },
            },
        )
        put(
            "toolsets/orphan_mcp/orphan_mcp.json",
            {
                "displayName": "orphan_mcp",
                "mcpToolset": {
                    "serverAddress": "https://orphan-111122223333.us-central1.run.app/mcp"
                },
            },
        )
    return buf.getvalue()


def test_contract_real_export_manifest_feeds_prepare_passport_push(
    mock_apps_client: typing.Any, tmp_path: Path
) -> None:
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(app_content=_contract_source_zip())
    mock_apps_client.export_app.return_value = lro
    with mock.patch.object(
        sys,
        "argv",
        [
            "cxas",
            "pull",
            SRC_APP,
            "--target-dir",
            str(tmp_path / "ws"),
            "--passport",
            "--no-live-introspect",
        ],
    ):
        main_cli.main()
    app_root = tmp_path / "ws" / "Sample_Agent"

    manifest_file = app_root / "passport" / "manifest.json"
    manifest = json.loads(manifest_file.read_text())

    assert manifest["schema_version"] == "4.0"
    assert manifest["bundle_layout"] == "passport-v4"
    assert manifest["agent"]["active_toolsets"] == ["mcp_main"]
    assert [p["name"] for p in manifest["agent"]["pruned_orphan_toolsets"]] == [
        "orphan_mcp"
    ]
    assert manifest["source"]["project_id"] == "${GCP_PROJECT}"
    ph = manifest["placeholders"]
    assert {"GCP_PROJECT", "GCP_PROJECT_NUMBER"} <= set(ph)
    gp_files = {o["file"] for o in ph["GCP_PROJECT"]["occurrences"]}
    assert "tools/lookup_order/python_function/python_code.py" in gp_files
    assert {o["file"] for o in ph["GCP_PROJECT_NUMBER"]["occurrences"]} >= {
        "toolsets/mcp_main/mcp_main.json"
    }
    assert all(
        isinstance(o["line"], int) and o["line"] > 0
        for o in ph["GCP_PROJECT"]["occurrences"]
    )
    assert ph["GCP_PROJECT_NUMBER"]["required_for_push"] is True
    assert [d["name"] for d in manifest["resources"]["bigquery"]] == [
        "billing_ds"
    ]
    assert [s["service"] for s in manifest["resources"]["cloud_run"]] == [
        "mcp-toolbox"
    ]
    assert manifest["introspection"]["live"] is False
    blob = json.dumps(manifest)
    assert "source-proj-111" not in blob
    assert "111122223333" not in blob

    stg = tmp_path / "stg"
    for rel in ("app.json", "agents", "tools", "toolsets"):
        src = app_root / rel
        if src.is_dir():
            shutil.copytree(src, stg / rel)
        elif src.is_file():
            stg.mkdir(parents=True, exist_ok=True)
            (stg / rel).write_bytes(src.read_bytes())
    real_prune = passport_push._prune_orphan_toolsets
    with mock.patch.object(
        passport_push, "_prune_orphan_toolsets", wraps=real_prune
    ) as spy:
        report = passport_push.prepare_passport_push(
            staging_dir=stg,
            source_app_dir=app_root,
            target_project_id="tgt-proj",
            target_location="us",
            strict_gates=True,
            project_number_resolver=lambda pid: (
                "123456789012" if pid == "tgt-proj" else None
            ),
        )
    seen = spy.call_args.args[3]
    assert seen == {
        "active_toolsets": ["mcp_main"],
        "pruned_orphans": ["orphan_mcp"],
    }
    assert report["bundle_layout"] == "passport-v4"
    assert (
        report["resolved_parameters"]["target_project_number"] == "123456789012"
    )
    assert (
        report["placeholder_values"]["GCP_PROJECT_NUMBER"]["from"]
        == "looked up from the project ID"
    )
    assert report["unresolved_placeholders"] == []
    assert report["manifest_path"] == str(manifest_file.resolve())
    staged_ts = json.loads(
        (stg / "toolsets" / "mcp_main" / "mcp_main.json").read_text()
    )
    assert (
        staged_ts["mcpToolset"]["serverAddress"]
        == "https://mcp-toolbox-123456789012.us-central1.run.app/mcp"
    )


# ---- push gates and the post-upload read-back check ----


def _retail_source_zip(model: str | None = "gemini-3.0-flash-001") -> bytes:
    """A source app like the Retail agent: MCP toolset on a Cloud Run URL with the project number."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:

        def put(rel: str, data: typing.Any) -> None:
            zf.writestr(
                f"Retail_Agent/{rel}",
                data if isinstance(data, str) else json.dumps(data, indent=2),
            )

        app = {"displayName": "Retail Agent", "rootAgent": "order_agent"}
        if model:
            app["modelSettings"] = {"model": model}
        put("app.json", app)
        put(
            "agents/order_agent/order_agent.json",
            {
                "displayName": "order_agent",
                "instruction": "agents/order_agent/instruction.txt",
                "tools": ["get_policy", "end_session"],
                "toolsets": [
                    {
                        "toolset": "retail_toolbox",
                        "toolIds": ["get_order_details"],
                    }
                ],
            },
        )
        put("agents/order_agent/instruction.txt", "Use {@TOOL: get_policy}.\n")
        put(
            "tools/get_policy/get_policy.json",
            {
                "displayName": "get_policy",
                "pythonFunction": {
                    "name": "get_policy",
                    "pythonCode": "tools/get_policy/python_function/python_code.py",
                },
            },
        )
        put(
            "tools/get_policy/python_function/python_code.py",
            '_URI = "gs://src-proj-42-kb/policies/returns.md"\n'
            'def get_policy() -> dict:\n    return {"uri": _URI}\n',
        )
        put(
            "toolsets/retail_toolbox/retail_toolbox.json",
            {
                "name": "retail_toolbox",
                "displayName": "retail_toolbox",
                "mcpToolset": {
                    "serverAddress": "https://retail-toolbox-111122223333.us-central1.run.app/mcp",
                    "apiAuthentication": {"serviceAgentIdTokenAuthConfig": {}},
                },
            },
        )
    return buf.getvalue()


def _retail_pull(mock_apps_client: typing.Any, tmp_path: Path) -> Path:
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(app_content=_retail_source_zip())
    mock_apps_client.export_app.return_value = lro
    with mock.patch.object(
        sys,
        "argv",
        [
            "cxas",
            "pull",
            "projects/src-proj-42/locations/us/apps/a1",
            "--target-dir",
            str(tmp_path / "ws"),
            "--passport",
            "--no-live-introspect",
        ],
    ):
        main_cli.main()
    return tmp_path / "ws" / "Retail_Agent"


def _export_returns(mock_apps_client: typing.Any, content: bytes) -> None:
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(app_content=content)
    mock_apps_client.export_app.return_value = lro


def _pushed_copy_zip(
    uploaded: bytes, drop_toolset: bool = False, drop_model: bool = False
) -> bytes:
    """What CES returns on export after the import (optionally losing things)."""
    out = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(uploaded)) as src,
        zipfile.ZipFile(out, "w") as dst,
    ):
        for name in src.namelist():
            if name.endswith("/"):
                continue
            data = src.read(name).decode("utf-8")
            rel = name.removeprefix("agent/")
            if drop_toolset and rel.startswith("toolsets/"):
                continue
            if drop_toolset and rel == "agents/order_agent/order_agent.json":
                agent = json.loads(data)
                agent.pop("toolsets", None)
                data = json.dumps(agent)
            if drop_model and rel == "app.json":
                app = json.loads(data)
                app.pop("modelSettings", None)
                data = json.dumps(app)
            dst.writestr(f"Retail_Agent/{rel}", data)
    return out.getvalue()


def test_parser_push_passport_project_number_and_set_flags() -> None:
    args = get_parser().parse_args(
        [
            "push",
            "--app-dir",
            "/tmp/a",
            "--passport",
            "--project-id",
            "p",
            "--project-number",
            "123",
            "--set",
            "GCS_BUCKET_KB=kb-1",
            "--set",
            "${CLOUD_RUN_URL_X}=https://x",
        ]
    )
    assert args.project_number == "123"
    assert args.set_values == [
        "GCS_BUCKET_KB=kb-1",
        "${CLOUD_RUN_URL_X}=https://x",
    ]
    assert cli_app._parse_set_values(args.set_values) == {
        "GCS_BUCKET_KB": "kb-1",
        "CLOUD_RUN_URL_X": "https://x",
    }


def test_cli_push_passport_unresolved_project_number_stops_before_upload(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Gate 6 stops the push before the upload when ${GCP_PROJECT_NUMBER} is unresolved."""
    app_root = _retail_pull(mock_apps_client, tmp_path)
    toolset = app_root / "toolsets" / "retail_toolbox" / "retail_toolbox.json"
    assert (
        "https://retail-toolbox-${GCP_PROJECT_NUMBER}.us-central1.run.app/mcp"
        in toolset.read_text()
    )
    capsys.readouterr()
    with pytest.raises(SystemExit) as excinfo:
        _push(
            [
                "--app-dir",
                str(app_root),
                "--project-id",
                "tgt-proj",
                "--location",
                "us",
                "--display-name",
                "Copy",
                "--passport",
            ]
        )
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Gate 6" in out
    assert (
        "toolsets/retail_toolbox/retail_toolbox.json:5 still holds ${GCP_PROJECT_NUMBER}"
        in out
    )
    mock_apps_client.import_app.assert_not_called()
    mock_apps_client.import_as_new_app.assert_not_called()
    assert not (app_root / "passport" / "ledger.jsonl").exists()


def test_cli_push_passport_project_number_flag_stamps_and_read_back_passes(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app_root = _retail_pull(mock_apps_client, tmp_path)
    imported = mock.MagicMock()
    imported.name = "projects/tgt-proj/locations/us/apps/new-copy"
    mock_apps_client.import_as_new_app.return_value = mock.MagicMock(
        result=mock.MagicMock(return_value=imported)
    )

    def _import_then_export(**kwargs: typing.Any) -> typing.Any:
        _export_returns(
            mock_apps_client, _pushed_copy_zip(kwargs["app_content"])
        )
        return mock.MagicMock(result=mock.MagicMock(return_value=imported))

    mock_apps_client.import_as_new_app.side_effect = _import_then_export
    capsys.readouterr()
    _push(
        [
            "--app-dir",
            str(app_root),
            "--project-id",
            "tgt-proj",
            "--project-number",
            "999888777666",
            "--location",
            "us",
            "--display-name",
            "Copy",
            "--passport",
        ]
    )
    raw = mock_apps_client.import_as_new_app.call_args.kwargs["app_content"]
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        ts = json.loads(
            zf.read("agent/toolsets/retail_toolbox/retail_toolbox.json")
        )
        py = zf.read(
            "agent/tools/get_policy/python_function/python_code.py"
        ).decode()
    assert (
        ts["mcpToolset"]["serverAddress"]
        == "https://retail-toolbox-999888777666.us-central1.run.app/mcp"
    )
    assert '"gs://tgt-proj-kb/policies/returns.md"' in py
    out = capsys.readouterr().out
    assert "${GCP_PROJECT_NUMBER} = 999888777666 (--project-number)" in out
    assert (
        "the app read back from CES has the uploaded model, toolsets, tools and agent bindings"
        in out
    )
    assert (app_root / "passport" / "ledger.jsonl").is_file()


@pytest.mark.parametrize("skip_gates", [False, True])
def test_cli_push_passport_fails_when_ces_drops_toolset_or_model(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    skip_gates: bool,
) -> None:
    """The read-back check turns dropped toolsets or models into a failed push unless --skip-passport-gates."""
    app_root = _retail_pull(mock_apps_client, tmp_path)
    imported = mock.MagicMock()
    imported.name = "projects/tgt-proj/locations/us/apps/new-copy"

    def _import_then_export(**kwargs: typing.Any) -> typing.Any:
        _export_returns(
            mock_apps_client,
            _pushed_copy_zip(
                kwargs["app_content"], drop_toolset=True, drop_model=True
            ),
        )
        return mock.MagicMock(result=mock.MagicMock(return_value=imported))

    mock_apps_client.import_as_new_app.side_effect = _import_then_export
    capsys.readouterr()
    argv = [
        "--app-dir",
        str(app_root),
        "--project-id",
        "tgt-proj",
        "--project-number",
        "999888777666",
        "--location",
        "us",
        "--display-name",
        "Copy",
        "--passport",
    ]
    if skip_gates:
        _push([*argv, "--skip-passport-gates"])
    else:
        with pytest.raises(SystemExit) as excinfo:
            _push(argv)
        assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "toolset 'retail_toolbox' is missing from the app" in out
    assert (
        "agent 'order_agent' lost its binding to toolset 'retail_toolbox'"
        in out
    )
    assert (
        "model: the upload declares 'gemini-3.0-flash-001' but the app has no model"
        in out
    )
    assert ("Push FAILED the post-upload check" in out) is (not skip_gates)
    assert (app_root / "passport" / "ledger.jsonl").is_file()


def test_cli_push_passport_invalid_set_value_exits(
    mock_apps_client: typing.Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app_root = _retail_pull(mock_apps_client, tmp_path)
    capsys.readouterr()
    with pytest.raises(SystemExit) as excinfo:
        _push(
            [
                "--app-dir",
                str(app_root),
                "--project-id",
                "tgt-proj",
                "--location",
                "us",
                "--passport",
                "--set",
                "lower_case=x",
            ]
        )
    assert excinfo.value.code == 1
    assert "is not a placeholder name" in capsys.readouterr().out
    mock_apps_client.import_as_new_app.assert_not_called()
