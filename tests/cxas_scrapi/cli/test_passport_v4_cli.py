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

"""`cxas pull --passport` flags: --strict (and no --passport-legacy any more)."""

from __future__ import annotations

import io
import json
import os
import select
import subprocess
import sys
import typing
import zipfile
from unittest import mock

import pytest

from cxas_scrapi.cli import app as cli_app
from cxas_scrapi.cli import main as main_cli
from cxas_scrapi.cli.main import get_parser
from cxas_scrapi.utils.passport.export import PassportReadError

if typing.TYPE_CHECKING:
    from pathlib import Path

APP = "projects/src-proj-123/locations/us/apps/00000000-0000-4000-8000-0000000000aa"
NOT_READABLE = {
    "id": "projects/${GCP_PROJECT}/locations/us/collections/default_collection/dataStores/policy-docs",
    "kind": "discoveryengine.dataStore",
    "error": "HTTP 403: Permission 'discoveryengine.dataStores.get' denied",
    "error_category": "permission_denied",
    "missing_permission": "roles/discoveryengine.viewer (permission discoveryengine.dataStores.get)",
}


@pytest.fixture
def apps_client() -> typing.Any:
    with mock.patch("cxas_scrapi.cli.app.Apps", autospec=True) as apps_class:
        client = apps_class.return_value
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "Order_Desk/app.json",
                json.dumps({"displayName": "Order Desk", "rootAgent": "desk"}),
            )
            zf.writestr(
                "Order_Desk/agents/desk/desk.json",
                json.dumps({"displayName": "desk"}),
            )
        lro = mock.MagicMock()
        lro.result.return_value = mock.MagicMock(app_content=buf.getvalue())
        client.export_app.return_value = lro
        yield client


@pytest.fixture
def export_mock(monkeypatch: pytest.MonkeyPatch) -> mock.MagicMock:
    run = mock.MagicMock(
        return_value={"pruned_orphans": [], "parameterized_files": []}
    )
    monkeypatch.setattr(
        "cxas_scrapi.utils.passport.export.run_passport_export", run
    )
    return run


def _pull(target: Path, *flags: str) -> None:
    argv = ["cxas", "pull", APP, "--target-dir", str(target), *flags]
    with mock.patch.object(sys, "argv", argv):
        main_cli.main()


def test_parser_pull_strict_flag_and_no_legacy_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = get_parser().parse_args(["pull", "my-app"])
    assert args.strict is False
    assert not hasattr(args, "passport_legacy")
    args = get_parser().parse_args(["pull", "my-app", "--passport", "--strict"])
    assert args.strict is True
    with pytest.raises(SystemExit) as excinfo:
        get_parser().parse_args(
            ["pull", "my-app", "--passport", "--passport-legacy"]
        )
    assert excinfo.value.code == 2
    assert (
        "unrecognized arguments: --passport-legacy" in capsys.readouterr().err
    )


def test_passport_pull_defaults_to_layout_v4_options(
    apps_client: typing.Any, export_mock: mock.MagicMock, tmp_path: Path
) -> None:
    _pull(tmp_path / "ws", "--passport")
    kwargs = export_mock.call_args.kwargs
    assert "strict" not in kwargs
    assert kwargs["live_introspect"] is True


def test_unreadable_resource_warns_and_exits_zero(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    export_mock.return_value = {
        "pruned_orphans": [],
        "parameterized_files": [],
        "not_readable": [NOT_READABLE],
    }
    _pull(tmp_path / "ws", "--passport")
    out = capsys.readouterr().out
    assert "WARNING not readable: 1 resource(s)" in out
    assert "roles/discoveryengine.viewer" in out


def test_unreadable_part_says_what_could_not_be_read(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    part = {
        "id": "projects/${GCP_PROJECT}/secrets/toolbox-config/versions/latest",
        "kind": "secretmanager.payload",
        "what": "MCP server config (/app/tools.yaml) in secret `toolbox-config`",
        "error": "HTTP 403: Permission 'secretmanager.versions.access' denied",
        "missing_permission": "roles/secretmanager.secretAccessor",
    }
    export_mock.return_value = {
        "pruned_orphans": [],
        "parameterized_files": [],
        "not_readable": [part],
    }
    _pull(tmp_path / "ws", "--passport")
    out = capsys.readouterr().out
    assert (
        "versions/latest (MCP server config (/app/tools.yaml) in secret "
        "`toolbox-config`): HTTP 403" in out
    )
    assert "(missing: roles/secretmanager.secretAccessor)" in out


def test_strict_fails_after_the_bundle_is_written(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = {
        "pruned_orphans": [],
        "parameterized_files": [],
        "not_readable": [NOT_READABLE],
    }
    export_mock.side_effect = PassportReadError(report)
    with pytest.raises(SystemExit) as excinfo:
        _pull(tmp_path / "ws", "--passport", "--strict")
    assert excinfo.value.code == 1
    assert export_mock.call_args.kwargs["strict"] is True
    out = capsys.readouterr().out
    assert "WARNING not readable: 1 resource(s)" in out
    assert "Error: --strict: resources not readable:" in out
    assert "the bundle was written" in out


# A failed CES export fails `cxas pull --passport` exactly like a plain pull:
# exit 1, nothing written, no passport export (no fabricated starter bundle).


@pytest.mark.parametrize(
    "flags", [(), ("--passport",), ("--passport", "--strict")]
)
def test_failed_export_fails_the_pull_like_a_plain_pull(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    flags: tuple[str, ...],
) -> None:
    apps_client.export_app.side_effect = RuntimeError(
        "403 Permission 'ces.apps.export' denied on resource"
    )
    target = tmp_path / "ws"
    with pytest.raises(SystemExit) as excinfo:
        _pull(target, *flags)
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Failed to pull app: 403 Permission 'ces.apps.export' denied" in out
    assert "CXAS Passport bundle exported" not in out
    export_mock.assert_not_called()
    assert not target.exists()


@pytest.mark.parametrize("flags", [(), ("--passport",)])
def test_empty_export_content_fails_the_pull_like_a_plain_pull(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    flags: tuple[str, ...],
) -> None:
    lro = mock.MagicMock()
    lro.result.return_value = mock.MagicMock(app_content=b"")
    apps_client.export_app.return_value = lro
    target = tmp_path / "ws"
    with pytest.raises(SystemExit) as excinfo:
        _pull(target, *flags)
    assert excinfo.value.code == 1
    assert "Failed to pull app:" in capsys.readouterr().out
    export_mock.assert_not_called()
    assert not any(target.rglob("*"))


def test_pull_passport_renders_progress_in_non_tty_and_tty(
    apps_client: typing.Any,
    export_mock: mock.MagicMock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _pull(tmp_path / "non_tty_live", "--passport")
    out = capsys.readouterr().out
    assert out.index("Successfully pulled app.") < out.index(
        "Introspecting GCP resources & building Passport bundle..."
    )
    assert out.index(
        "Introspecting GCP resources & building Passport bundle..."
    ) < out.index("CXAS Passport bundle exported:")

    _pull(tmp_path / "non_tty_offline", "--passport", "--no-live-introspect")
    out_offline = capsys.readouterr().out
    assert "Building Passport bundle..." in out_offline

    # Simulate an interactive terminal to verify rich square spinner + progress bar
    with (
        mock.patch(
            "rich.console.Console.is_terminal",
            new_callable=mock.PropertyMock,
            return_value=True,
        ),
        mock.patch(
            "rich.console.Console.is_dumb_terminal",
            new_callable=mock.PropertyMock,
            return_value=False,
        ),
        mock.patch("rich.progress.Progress.add_task") as mock_add_task,
    ):
        _pull(tmp_path / "tty_live", "--passport")
    mock_add_task.assert_called_once_with(
        "Introspecting GCP resources & building Passport bundle...",
        total=None,
    )


def test_push_passport_prints_pull_style_summary_and_readiness_and_strict_mode(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app_root = tmp_path / "Sample_Agent"
    (app_root / "agents" / "root_agent").mkdir(parents=True)
    (app_root / "passport").mkdir(parents=True)
    (app_root / "app.json").write_text(
        json.dumps({"displayName": "Sample Agent", "rootAgent": "root_agent"})
    )
    (app_root / "agents" / "root_agent" / "root_agent.json").write_text(
        json.dumps(
            {
                "displayName": "root_agent",
                "instruction": "agents/root_agent/instruction.txt",
                "tools": ["end_session"],
            }
        )
    )
    (app_root / "agents" / "root_agent" / "instruction.txt").write_text(
        "Use {@TOOL: end_session}.\n"
    )
    (app_root / "passport" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "4.0",
                "bundle_layout": "passport-v4",
                "placeholders": {},
                "resources": {},
                "agent": {"active_toolsets": [], "pruned_orphan_toolsets": []},
            }
        )
    )

    sample_readiness = {
        "checked": True,
        "target_project_id": "tgt-proj",
        "ready": False,
        "summary": {
            "ready": 0,
            "missing": 1,
            "misconfigured": 0,
            "not_checked": 0,
        },
        "checks": [
            {
                "status": "MISSING",
                "kind": "bigquery.dataset",
                "resource": "BigQuery dataset `retail_support`",
                "detail": "dataset `tgt-proj.retail_support` does not exist",
                "remediation": "Run: passport/bigquery/retail_support/schema.sql",
            }
        ],
    }

    with mock.patch("cxas_scrapi.cli.app.Apps", autospec=True) as apps_cls:
        client = apps_cls.return_value
        imported = mock.MagicMock()
        imported.name = "projects/tgt-proj/locations/us/apps/new-copy"
        client.import_as_new_app.return_value = mock.MagicMock(
            result=mock.MagicMock(return_value=imported)
        )
        # export_app for post-upload verify_pushed_app
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for rel in (
                "app.json",
                "agents/root_agent/root_agent.json",
                "agents/root_agent/instruction.txt",
            ):
                zf.write(app_root / rel, f"Sample_Agent/{rel}")
        client.export_app.return_value = mock.MagicMock(
            result=mock.MagicMock(
                return_value=mock.MagicMock(app_content=buf.getvalue())
            )
        )

        with (
            mock.patch(
                "cxas_scrapi.utils.passport.readiness.audit_target_readiness",
                return_value=sample_readiness,
            ),
            mock.patch.object(
                sys,
                "argv",
                [
                    "cxas",
                    "push",
                    "--app-dir",
                    str(app_root),
                    "--project-id",
                    "tgt-proj",
                    "--location",
                    "us",
                    "--display-name",
                    "Copy",
                    "--passport",
                ],
            ),
        ):
            main_cli.main()

        out = capsys.readouterr().out
        assert "CXAS Passport bundle pushed:" in out
        assert "CXAS Passport target readiness:" in out
        assert "• BigQuery (1 dataset)" in out
        assert "[MISSING] retail_support:" in out
        assert "-> Run: passport/bigquery/retail_support/schema.sql" in out
        assert "Passport latency:" not in out

        # --strict fails (exit 1) when readiness is not ready
        with (
            mock.patch(
                "cxas_scrapi.utils.passport.readiness.audit_target_readiness",
                return_value=sample_readiness,
            ),
            mock.patch.object(
                sys,
                "argv",
                [
                    "cxas",
                    "push",
                    "--app-dir",
                    str(app_root),
                    "--project-id",
                    "tgt-proj",
                    "--location",
                    "us",
                    "--display-name",
                    "Copy",
                    "--passport",
                    "--strict",
                ],
            ),
            pytest.raises(SystemExit) as excinfo,
        ):
            main_cli.main()
        assert excinfo.value.code == 1
        assert "Push FAILED --strict:" in capsys.readouterr().out

        # --strict exits 0 when ready=True
        ready_report = {
            **sample_readiness,
            "ready": True,
            "summary": {
                "ready": 1,
                "missing": 0,
                "misconfigured": 0,
                "not_checked": 0,
            },
            "checks": [
                {
                    "status": "READY",
                    "kind": "bigquery.dataset",
                    "resource": "BigQuery dataset `retail_support`",
                    "detail": "dataset and 5 table(s) present",
                    "remediation": None,
                }
            ],
        }
        with (
            mock.patch(
                "cxas_scrapi.utils.passport.readiness.audit_target_readiness",
                return_value=ready_report,
            ),
            mock.patch.object(
                sys,
                "argv",
                [
                    "cxas",
                    "push",
                    "--app-dir",
                    str(app_root),
                    "--project-id",
                    "tgt-proj",
                    "--location",
                    "us",
                    "--display-name",
                    "Copy",
                    "--passport",
                    "--strict",
                ],
            ),
        ):
            main_cli.main()
        assert "all attached resources Ready" in capsys.readouterr().out


def test_passport_progress_pty_utf8_and_ascii_fallback() -> None:
    if os.name != "posix":
        pytest.skip("PTY test requires POSIX")
    import pty  # noqa: PLC0415

    script = (
        "import time\n"
        "from cxas_scrapi.cli.app import _passport_progress\n"
        "with _passport_progress('Working...'):\n"
        "    time.sleep(0.2)\n"
        "print('DONE')\n"
    )
    for io_enc, expect_square in (("utf-8", True), ("ascii", False)):
        master, slave = pty.openpty()
        env = dict(os.environ, TERM="xterm-256color", PYTHONIOENCODING=io_enc)
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        chunks: list[bytes] = []
        while True:
            ready, _, _ = select.select([master], [], [], 5.0)
            if not ready:
                break
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        os.close(master)
        assert proc.wait(timeout=5) == 0
        raw = b"".join(chunks).decode("utf-8", errors="replace")
        assert "DONE" in raw
        assert "Working..." in raw
        if expect_square:
            assert any(ch in raw for ch in "◰◳◲◱")
            assert "✓" in raw
        else:
            assert "+" in raw


def test_push_summary_surfaces_gate_warnings_and_env_resolved_project(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli_app._print_passport_push_summary(
        source_app_dir=str(tmp_path),
        app_name="projects/env-proj/locations/us/apps/a1",
        target_project_id="env-proj",
        target_location="us",
        stamp_report={
            "pruned_orphans": [],
            "stamped_files_count": 2,
            "gates_passed": False,
            "fatal_passed": True,
            "invariant_report": {
                "errors": [],
                "warnings": ["Hardcoded 6-digit OTP '384920' detected"],
            },
        },
        check={"checked": True, "ok": True, "problems": [], "warnings": []},
        skip_gates=False,
    )
    out = capsys.readouterr().out
    assert "Target project:      env-proj (us)" in out
    assert "Pre-push gates:      PASSED (with warnings)" in out
    assert "WARN:  Hardcoded 6-digit OTP '384920' detected" in out
    assert "\x1b[" not in out  # captured (non-terminal) output stays plain


@pytest.mark.parametrize(
    ("stamp_report", "check", "gates", "read_back"),
    [
        (
            {"gates_passed": True},
            {"checked": True, "problems": [], "warnings": []},
            "\x1b[32mPASSED\x1b[0m",
            "\x1b[32mPASSED\x1b[0m — the app read back from CES has",
        ),
        (
            {
                "gates_passed": False,
                "fatal_passed": False,
                "invariant_report": {"errors": ["Gate 6: ${GCP_PROJECT} left"]},
            },
            {"checked": True, "problems": ["model dropped"], "warnings": []},
            "\x1b[31mFAILED\x1b[0m",
            "\x1b[31mFAILED\x1b[0m — the app read back from CES lacks",
        ),
    ],
)
def test_push_summary_grades_statuses_on_terminals(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stamp_report: dict[str, typing.Any],
    check: dict[str, typing.Any],
    gates: str,
    read_back: str,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    cli_app._print_passport_push_summary(
        source_app_dir="/tmp/app",
        app_name="projects/p/locations/us/apps/a1",
        target_project_id="p",
        target_location="us",
        stamp_report=stamp_report,
        check=check,
        skip_gates=False,
    )
    out = capsys.readouterr().out
    assert f"Pre-push gates:      {gates}" in out
    assert f"CES read-back:       {read_back}" in out
    if stamp_report.get("invariant_report"):
        assert "\x1b[31mERROR:\x1b[0m Gate 6" in out
        assert "\x1b[31mRead-back issues:\x1b[0m" in out
