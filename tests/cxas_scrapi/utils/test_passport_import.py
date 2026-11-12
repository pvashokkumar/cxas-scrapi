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

"""Unit tests for cxas_scrapi.utils.passport.{push,gates,verify}."""

from __future__ import annotations

import io
import json
import shutil
import typing
import zipfile
from typing import TYPE_CHECKING

import pytest
from passport_fakes import (
    KB_BUCKET,
    SRC_NUMBER,
    SRC_PROJECT,
    snapshot,
    write,
    write_retail_agent,
)
from passport_v4_cloud import CRM, GCS, FakeCloud

from cxas_scrapi.utils.passport import push as passport_push
from cxas_scrapi.utils.passport.export import run_passport_export
from cxas_scrapi.utils.passport.http import ApiReader
from cxas_scrapi.utils.passport.push import (
    compare_pushed_app,
    post_passport_push,
    prepare_passport_push,
    verify_passport_invariants,
    verify_pushed_app,
)

if TYPE_CHECKING:
    from pathlib import Path


def _w(path: Path, data: typing.Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        data if isinstance(data, str) else json.dumps(data, indent=2),
        encoding="utf-8",
    )


def _create_valid_ces_app(base_dir: Path) -> Path:
    """Create a valid two-agent CES bundle for testing Gates 1 through 5."""
    _w(
        base_dir / "app.json",
        {"displayName": "Valid App", "rootAgent": "Root Agent"},
    )
    _w(
        base_dir / "agents/Root_Agent/Root_Agent.json",
        {
            "displayName": "Root Agent",
            "instruction": "agents/Root_Agent/instruction.txt",
            "childAgents": ["Billing Agent"],
            "tools": ["lookup_account"],
            "toolsets": [{"toolset": "BillingMcp"}],
            "afterModelCallbacks": [
                {
                    "description": "Sanitize output",
                    "pythonCode": "agents/Root_Agent/after_model_callbacks/sanitize/python_code.py",
                }
            ],
        },
    )
    _w(
        base_dir / "agents/Root_Agent/instruction.txt",
        "Use {@TOOL: lookup_account} then transfer to {@AGENT: Billing Agent}.\n",
    )
    _w(
        base_dir
        / "agents/Root_Agent/after_model_callbacks/sanitize/python_code.py",
        "def after_model_callback(callback_context, llm_response):\n"
        "  try:\n"
        "    return None\n"
        "  except Exception:\n"
        "    return None\n",
    )
    _w(
        base_dir / "agents/Billing_Agent/Billing_Agent.json",
        {
            "displayName": "Billing Agent",
            "instruction": "agents/Billing_Agent/instruction.txt",
            "tools": ["lookup_account"],
        },
    )
    _w(
        base_dir / "agents/Billing_Agent/instruction.txt",
        "Check account using {@TOOL: lookup_account}.\n",
    )
    _w(
        base_dir / "tools/lookup_account/lookup_account.json",
        {
            "displayName": "lookup_account",
            "pythonFunction": {
                "name": "lookup_account",
                "pythonCode": "tools/lookup_account/python_function/python_code.py",
            },
        },
    )
    _w(
        base_dir / "tools/lookup_account/python_function/python_code.py",
        "def lookup_account(params: dict) -> dict:\n"
        '  return {"status": "OK"}\n',
    )
    _w(
        base_dir / "toolsets/BillingMcp/BillingMcp.json",
        {
            "displayName": "BillingMcp",
            "mcpToolset": {"serverAddress": "https://toolbox.run.app/mcp"},
        },
    )
    return base_dir


def test_verify_passport_invariants_gates(tmp_path: Path) -> None:
    """Test Gates 1 through 5 of verify_passport_invariants."""
    # Gate 1 failure: missing app.json
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="Gate 1"):
        verify_passport_invariants(empty_dir, strict_gates=True)

    # Valid app passes all 5 gates
    app_dir = _create_valid_ces_app(tmp_path / "valid_app")
    res = verify_passport_invariants(app_dir, strict_gates=True)
    assert res["fatal_passed"] is True
    assert res["gates_passed"] is True

    # Gate 2 warning: orphan agent
    orphan_dir = app_dir / "agents" / "Orphan_Agent"
    _w(orphan_dir / "Orphan_Agent.json", {"displayName": "Orphan Agent"})
    res_g2 = verify_passport_invariants(app_dir, strict_gates=True)
    assert res_g2["fatal_passed"] is True
    assert res_g2["gates"]["gate2_agent_graph"]["passed"] is False
    assert any(
        "Orphan Agent" in issue
        for issue in res_g2["gates"]["gate2_agent_graph"]["issues"]
    )
    shutil.rmtree(orphan_dir)

    # Gate 3 failure: {@TOOL: ghost_tool} in instruction.txt but not in agent.json
    root_instr = app_dir / "agents" / "Root_Agent" / "instruction.txt"
    orig_instr = root_instr.read_text(encoding="utf-8")
    root_instr.write_text(
        orig_instr + "\nCall {@TOOL: ghost_tool}.\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="ghost_tool"):
        verify_passport_invariants(app_dir, strict_gates=True)
    root_instr.write_text(orig_instr, encoding="utf-8")

    # Gate 4 failure: broken Python syntax in tool
    py_path = (
        app_dir
        / "tools"
        / "lookup_account"
        / "python_function"
        / "python_code.py"
    )
    orig_py = py_path.read_text(encoding="utf-8")
    py_path.write_text("def broken(:\n  pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Gate 4"):
        verify_passport_invariants(app_dir, strict_gates=True)
    res_non_strict = verify_passport_invariants(app_dir, strict_gates=False)
    assert res_non_strict["fatal_passed"] is False
    assert res_non_strict["gates"]["gate4_python_ast"]["passed"] is False
    py_path.write_text(orig_py, encoding="utf-8")

    # Gate 5 warnings: hardcoded OTP "384920", deep output_schema, unsafe after_model_callback
    root_instr.write_text(
        orig_instr + "\nUse hardcoded OTP 384920.\n", encoding="utf-8"
    )
    child_json_path = (
        app_dir / "agents" / "Billing_Agent" / "Billing_Agent.json"
    )
    child_data = json.loads(child_json_path.read_text(encoding="utf-8"))
    child_data["outputSchema"] = {
        "type": "OBJECT",
        "properties": {
            "level1": {
                "type": "OBJECT",
                "properties": {
                    "level2": {
                        "type": "OBJECT",
                        "properties": {"val": {"type": "STRING"}},
                    }
                },
            }
        },
    }
    child_json_path.write_text(json.dumps(child_data), encoding="utf-8")

    am_cb_path = (
        app_dir
        / "agents"
        / "Root_Agent"
        / "after_model_callbacks"
        / "sanitize"
        / "python_code.py"
    )
    am_cb_path.write_text(
        "def after_model_callback(callback_context, llm_response):\n"
        '  return {"bad": "raw_dict"}\n',
        encoding="utf-8",
    )

    res_g5 = verify_passport_invariants(app_dir, strict_gates=True)
    assert res_g5["fatal_passed"] is True
    assert res_g5["gates"]["gate5_live_voice_safety"]["passed"] is False
    g5_issues = "\n".join(res_g5["gates"]["gate5_live_voice_safety"]["issues"])
    assert "384920" in g5_issues
    assert "nested OBJECT depth" in g5_issues
    assert "try...except" in g5_issues
    assert "raw dict" in g5_issues


def test_verify_passport_invariants_gate1_blank_shell_app_json(
    tmp_path: Path,
) -> None:
    """Gate 1 on a blank-shell app.json (has app.json, no rootAgent, no agents/)."""
    stg = tmp_path / "stg"
    _w(stg / "app.json", {"name": "x", "displayName": "My New Agent"})
    with pytest.raises(ValueError, match="Gate 1") as exc:
        passport_push.verify_passport_invariants(stg, strict_gates=True)
    assert "Missing or empty 'rootAgent' field in app.json" in str(exc.value)
    rep = passport_push.verify_passport_invariants(stg, strict_gates=False)
    assert rep["fatal_passed"] is False


def test_prepare_passport_push_no_manifest_reports_none(tmp_path: Path) -> None:
    src = _create_valid_ces_app(tmp_path / "src")
    stg = tmp_path / "stg"
    shutil.copytree(src, stg)
    report = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=src,
        target_project_id="tgt-proj",
        target_location="us",
        strict_gates=True,
    )
    assert report["manifest_path"] is None
    assert report["fatal_passed"] is True


def test_prepare_passport_push_rejects_retired_v2_manifest_and_dataset_kwarg(
    tmp_path: Path,
) -> None:
    src = _create_valid_ces_app(tmp_path / "src")
    _w(
        src / "passport" / "manifest.json",
        {"schema_version": "2.0", "bundle_layout": "passport"},
    )
    stg = tmp_path / "stg"
    shutil.copytree(src, stg)
    with pytest.raises(ValueError, match="Unsupported passport schema_version"):
        prepare_passport_push(
            staging_dir=stg,
            source_app_dir=src,
            target_project_id="tgt-proj",
            target_location="us",
        )
    with pytest.raises(TypeError):
        prepare_passport_push(
            staging_dir=stg,
            source_app_dir=src,
            target_dataset="old_ds",  # type: ignore[call-arg]
        )


def test_prepare_passport_push_guards_same_source_dir_and_quotes_moh_uri_and_empty_app_json(
    tmp_path: Path,
) -> None:
    bundle = _create_valid_ces_app(tmp_path / "bundle")
    (bundle / ".git").mkdir()
    _w(bundle / "passport/manifest.json", {"schema_version": "4.0"})
    _w(bundle / "PLACEHOLDERS.md", "# guide\n")

    with pytest.raises(
        ValueError, match="staging_dir must be separate from source_app_dir"
    ):
        prepare_passport_push(
            staging_dir=bundle,
            source_app_dir=bundle,
            target_project_id="tgt-proj",
        )
    assert (bundle / ".git").is_dir()
    assert (bundle / "passport/manifest.json").is_file()
    assert (bundle / "PLACEHOLDERS.md").is_file()

    # Empty app.json ({}) still receives preserve_display_name, and --moh-uri quotes safely
    stg = tmp_path / "stg"
    shutil.copytree(bundle, stg)
    _w(stg / "app.json", {})
    cb = stg / "agents/Root_Agent/before_agent_callbacks/moh/python_code.py"
    _w(cb, '_MOH_AUDIO_URI = "gs://old/moh.wav"\n')
    rep = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id="tgt-proj",
        preserve_display_name="Preserved On Empty Dict",
        target_moh_uri='gs://bkt/quote"and\\slash.wav',
        strict_gates=False,
    )
    assert json.loads((stg / "app.json").read_text()) == {
        "displayName": "Preserved On Empty Dict"
    }
    assert rep["gates"]["gate_4"]["passed"] is True
    assert 'gs://bkt/quote\\"and\\\\slash.wav' in cb.read_text()


def test_post_passport_push_writes_ledger_inside_passport_folder(
    tmp_path: Path,
) -> None:
    src = tmp_path / "bundle"
    _w(src / "passport/manifest.json", {"schema_version": "4.0"})
    e1 = post_passport_push(
        source_app_dir=src,
        app_name="projects/p/locations/us/apps/a",
        created_version_name="projects/p/locations/us/apps/a/versions/v1",
        target_project_id="p",
        target_location="us",
        stamp_report={"gates_passed": True, "stamped_files_count": 3},
    )
    e2 = post_passport_push(
        source_app_dir=src,
        app_name="projects/p/locations/us/apps/a",
        target_project_id="p",
        target_location="us",
        stamp_report={"gates_passed": False, "stamped_files_count": 0},
    )
    lines = [
        json.loads(x)
        for x in (src / "passport" / "ledger.jsonl").read_text().splitlines()
        if x.strip()
    ]
    assert lines == [e1, e2]
    assert sorted(p.name for p in src.iterdir()) == ["passport"]


# ---------------------------------------------------------------------------
# Push of the bundles `cxas pull --passport` makes (layout v4)
# ---------------------------------------------------------------------------

SRC_APP = f"projects/{SRC_PROJECT}/locations/us/apps/00000000-0000-4000-8000-000000000002"
TGT_PROJECT = "tgt-proj"
TGT_NUMBER = "999888777666"
RETAIL_PARAMETERIZED = [
    "tools/check_return_eligibility/python_function/python_code.py",
    "tools/get_store_policy/python_function/python_code.py",
    "toolsets/retail_toolbox/retail_toolbox.json",
]


def _export(root: Path, routes: dict | None = None) -> None:
    """`cxas pull --passport` export of `root`: offline, or reading `routes` of the fake cloud."""
    run_passport_export(
        app_root=root,
        project_id=SRC_PROJECT,
        location="us",
        app_name=SRC_APP,
        live_introspect=routes is not None,
        reader=None
        if routes is None
        else ApiReader(FakeCloud(routes), sleep=lambda _s: None),
    )


def _retail_bundle(tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
    """A Retail-shaped bundle from the real export, plus the plain-pull files it came from."""
    root = write_retail_agent(tmp_path / "Retail_Order_Support_Chat_Agent")
    plain = snapshot(root)
    _export(root)
    return root, plain


def _stage(bundle: Path, dest: Path) -> Path:
    shutil.copytree(bundle, dest)
    return dest


def _numbers(pid: str) -> str | None:
    return {TGT_PROJECT: TGT_NUMBER, SRC_PROJECT: SRC_NUMBER}.get(pid)


def test_push_with_the_source_values_gives_back_the_plain_pull(
    tmp_path: Path,
) -> None:
    bundle, plain = _retail_bundle(tmp_path)
    stg = _stage(bundle, tmp_path / "stg")
    report = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id=SRC_PROJECT,
        target_location="us",
        project_number_resolver=_numbers,
    )
    assert report["bundle_layout"] == "passport-v4"
    # Same files, same bytes: the passport only swapped values for placeholders.
    assert snapshot(stg) == plain


def test_push_stamps_the_target_project(tmp_path: Path) -> None:
    bundle, _ = _retail_bundle(tmp_path)
    on_disk = snapshot(bundle)
    stg = _stage(bundle, tmp_path / "stg")
    report = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        project_number_resolver=_numbers,
    )
    toolset = json.loads(
        (stg / "toolsets/retail_toolbox/retail_toolbox.json").read_text()
    )
    assert (
        toolset["mcpToolset"]["serverAddress"]
        == f"https://retail-toolbox-{TGT_NUMBER}.us-central1.run.app/mcp"
    )
    code = (
        stg / "tools/get_store_policy/python_function/python_code.py"
    ).read_text()
    assert (
        f'"shipping": "gs://{TGT_PROJECT}-retail-kb/policies/shipping_policy.md"'
        in code
    )
    assert report["placeholder_values"]["GCP_PROJECT"] == {
        "value": TGT_PROJECT,
        "from": "--project-id",
    }
    assert report["placeholder_values"]["GCP_PROJECT_NUMBER"] == {
        "value": TGT_NUMBER,
        "from": "looked up from the project ID",
    }
    assert report["stamped_files"] == RETAIL_PARAMETERIZED
    assert report["unresolved_placeholders"] == []
    assert report["gates"]["gate_6"]["passed"] is True
    assert not (stg / "passport").exists()
    assert not (stg / "PLACEHOLDERS.md").exists()
    for rel, data in snapshot(stg).items():
        text = data.decode()
        assert SRC_PROJECT not in text, rel
        assert SRC_NUMBER not in text, rel
        assert KB_BUCKET not in text, rel
        assert "${GCP_" not in text, rel
    assert (
        "${amount:.2f}"
        in (stg / "agents/order_support_agent/instruction.txt").read_text()
    )  # not a placeholder
    assert snapshot(bundle) == on_disk  # the bundle keeps its placeholders


def test_push_stops_before_upload_when_the_project_number_is_unknown(
    tmp_path: Path,
) -> None:
    bundle, _ = _retail_bundle(tmp_path)
    with pytest.raises(ValueError, match=r"Gate 6") as exc:
        prepare_passport_push(
            staging_dir=_stage(bundle, tmp_path / "stg1"),
            source_app_dir=bundle,
            target_project_id=TGT_PROJECT,
            target_location="us",
            project_number_resolver=lambda pid: None,
        )
    message = str(exc.value)
    assert "[FAIL] Gate 6" in message
    assert (
        "toolsets/retail_toolbox/retail_toolbox.json:5 still holds ${GCP_PROJECT_NUMBER}"
        in message
    )
    assert "--project-number" in message
    report = prepare_passport_push(
        staging_dir=_stage(bundle, tmp_path / "stg2"),
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        strict_gates=False,
        project_number_resolver=lambda pid: None,
    )
    assert report["fatal_passed"] is False
    assert report["unresolved_placeholders"] == [
        {
            "file": "toolsets/retail_toolbox/retail_toolbox.json",
            "line": 5,
            "placeholder": "GCP_PROJECT_NUMBER",
        }
    ]


def test_push_project_number_flag_and_toolbox_url_host(
    tmp_path: Path,
) -> None:
    bundle, _ = _retail_bundle(tmp_path)
    report = prepare_passport_push(
        staging_dir=_stage(bundle, tmp_path / "stg1"),
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        target_project_number="123412341234",
        project_number_resolver=_numbers,
    )
    assert report["placeholder_values"]["GCP_PROJECT_NUMBER"] == {
        "value": "123412341234",
        "from": "--project-number",
    }
    # --toolbox-url: the number comes from its host and every MCP toolset points at it.
    stg = _stage(bundle, tmp_path / "stg2")
    report = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        target_toolbox_url="https://my-toolbox-555444333222.europe-west1.run.app",
        project_number_resolver=_numbers,
    )
    assert report["placeholder_values"]["GCP_PROJECT_NUMBER"] == {
        "value": "555444333222",
        "from": "the --toolbox-url host",
    }
    toolset = json.loads(
        (stg / "toolsets/retail_toolbox/retail_toolbox.json").read_text()
    )
    assert (
        toolset["mcpToolset"]["serverAddress"]
        == "https://my-toolbox-555444333222.europe-west1.run.app/mcp"
    )


def test_push_set_value_that_breaks_json_is_refused(tmp_path: Path) -> None:
    bundle, _ = _retail_bundle(tmp_path)
    with pytest.raises(
        ValueError,
        match=r"retail_toolbox\.json: a placeholder value breaks the JSON",
    ):
        prepare_passport_push(
            staging_dir=_stage(bundle, tmp_path / "stg"),
            source_app_dir=bundle,
            target_project_id=TGT_PROJECT,
            target_location="us",
            placeholder_values={"GCP_PROJECT_NUMBER": '12"34'},
            project_number_resolver=_numbers,
        )


def _hold_music_bundle(tmp_path: Path) -> Path:
    root = tmp_path / "Hold"
    write(root / "app.json", {"displayName": "Hold", "rootAgent": "greeter"})
    write(
        root / "agents/greeter/greeter.json",
        {
            "displayName": "greeter",
            "instruction": "agents/greeter/instruction.txt",
            "beforeAgentCallbacks": [
                {
                    "pythonCode": "agents/greeter/before_agent_callbacks/moh/python_code.py"
                }
            ],
        },
    )
    write(root / "agents/greeter/instruction.txt", "Greet the caller.\n")
    write(
        root / "agents/greeter/before_agent_callbacks/moh/python_code.py",
        '_MOH_AUDIO_URI = "gs://hold-music-audio/hold_music_01.raw"\n',
    )
    _export(
        root,
        {
            ("GET", f"{CRM}/{SRC_PROJECT}"): (
                200,
                {"projectId": SRC_PROJECT, "projectNumber": SRC_NUMBER},
            ),
            ("GET", f"{GCS}/hold-music-audio"): (
                200,
                {
                    "name": "hold-music-audio",
                    "projectNumber": SRC_NUMBER,
                    "location": "US",
                },
            ),
        },
    )
    return root


def test_push_bucket_placeholder_needs_a_set_value(tmp_path: Path) -> None:
    bundle = _hold_music_bundle(tmp_path)
    report = prepare_passport_push(
        staging_dir=_stage(bundle, tmp_path / "stg1"),
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        strict_gates=False,
        project_number_resolver=_numbers,
    )
    gate6 = report["gates"]["gate_6"]
    assert gate6["passed"] is False
    assert gate6["errors"] == [
        "agents/greeter/before_agent_callbacks/moh/python_code.py:1 still holds ${GCS_BUCKET_HOLD_MUSIC_AUDIO} "
        "(set it with: cxas push --passport --set GCS_BUCKET_HOLD_MUSIC_AUDIO=<BUCKET>)"
    ]
    stg = _stage(bundle, tmp_path / "stg2")
    report = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        strict_gates=False,
        project_number_resolver=_numbers,
        placeholder_values={"GCS_BUCKET_HOLD_MUSIC_AUDIO": "tgt-hold-music"},
    )
    assert report["gates"]["gate_6"]["passed"] is True
    assert (
        stg / "agents/greeter/before_agent_callbacks/moh/python_code.py"
    ).read_text() == (
        '_MOH_AUDIO_URI = "gs://tgt-hold-music/hold_music_01.raw"\n'
    )
    assert report["placeholder_values"]["GCS_BUCKET_HOLD_MUSIC_AUDIO"] == {
        "value": "tgt-hold-music",
        "from": "--set",
    }


# ---------------------------------------------------------------------------
# After the upload: read the app back and compare
# ---------------------------------------------------------------------------


class _Lro:
    def __init__(self, content: bytes | Exception) -> None:
        self._content = content

    def result(self) -> typing.Any:
        if isinstance(self._content, Exception):
            raise self._content
        return type("Response", (), {"app_content": self._content})()


class _Apps:
    def __init__(self, content: bytes | Exception) -> None:
        self.content = content
        self.exported: list[str] = []

    def export_app(self, app_name: str, app_version: str | None = None) -> _Lro:
        self.exported.append(app_name)
        return _Lro(self.content)


def _zip_tree(root: Path, top: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, f"{top}/{path.relative_to(root)}")
    return buf.getvalue()


def _staged_retail(tmp_path: Path) -> Path:
    bundle, _ = _retail_bundle(tmp_path)
    stg = _stage(bundle, tmp_path / "stg")
    prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id=TGT_PROJECT,
        target_location="us",
        project_number_resolver=_numbers,
    )
    return stg


def test_verify_pushed_app_passes_when_ces_kept_everything(
    tmp_path: Path,
) -> None:
    stg = _staged_retail(tmp_path)
    apps = _Apps(_zip_tree(stg, "Retail_Order_Support_Chat_Agent"))
    report = verify_pushed_app(
        apps, "projects/tgt-proj/locations/us/apps/new", stg
    )
    assert report == {
        "checked": True,
        "ok": True,
        "problems": [],
        "warnings": [],
    }
    assert apps.exported == ["projects/tgt-proj/locations/us/apps/new"]


def test_verify_pushed_app_reports_what_ces_dropped(tmp_path: Path) -> None:
    stg = _staged_retail(tmp_path)
    pushed = tmp_path / "pushed"
    shutil.copytree(stg, pushed)
    app = json.loads((pushed / "app.json").read_text())
    del app["modelSettings"]
    write(pushed / "app.json", app)
    shutil.rmtree(pushed / "toolsets/retail_toolbox")
    agent = json.loads(
        (
            pushed / "agents/order_support_agent/order_support_agent.json"
        ).read_text()
    )
    agent["toolsets"] = []
    agent["tools"] = ["end_session"]
    write(pushed / "agents/order_support_agent/order_support_agent.json", agent)
    report = verify_pushed_app(
        _Apps(_zip_tree(pushed, "Retail")),
        "projects/p/locations/us/apps/a",
        stg,
    )
    assert report["checked"] is True
    assert report["ok"] is False
    assert report["problems"] == [
        "model: the upload declares 'gemini-3.0-flash-001' but the app has no model (the platform default); "
        "CES drops a model that is not available in the app's location",
        "toolset 'retail_toolbox' is missing from the app (CES drops a toolset whose URL or authentication it cannot use)",
        "agent 'order_support_agent' lost its binding to toolset 'retail_toolbox'",
        "agent 'order_support_agent' lost tools ['check_return_eligibility', 'get_store_policy']",
    ]


def test_verify_pushed_app_unreadable_app_is_a_warning(tmp_path: Path) -> None:
    stg = _staged_retail(tmp_path)
    report = verify_pushed_app(
        _Apps(RuntimeError("403 denied")), "projects/p/locations/us/apps/a", stg
    )
    assert report["checked"] is False
    assert report["ok"] is True
    assert report["problems"] == []
    assert report["warnings"] == [
        "could not read the app back to check it: 403 denied"
    ]
    assert verify_pushed_app(None, None, stg)["warnings"] == [
        "no app to read back"
    ]


def test_compare_pushed_app_flags_placeholders_left_in_the_app(
    tmp_path: Path,
) -> None:
    stg = _staged_retail(tmp_path)
    pushed = tmp_path / "pushed"
    shutil.copytree(stg, pushed)
    (pushed / "agents/order_support_agent/instruction.txt").write_text(
        "Project ${GCP_PROJECT}; ${amount:.2f}\n"
    )
    assert compare_pushed_app(stg, pushed) == [
        "agents/order_support_agent/instruction.txt still holds ${GCP_PROJECT}"
    ]


def test_gates_and_push_reject_escaping_paths_child_staging_and_unused_wrappers(
    tmp_path: Path,
) -> None:
    outside_py = tmp_path / "outside.py"
    outside_py.write_text("x = 1\n", encoding="utf-8")
    outside_txt = tmp_path / "outside.txt"
    outside_txt.write_text("Outside prompt\n", encoding="utf-8")

    bundle = _create_valid_ces_app(tmp_path / "bundle")
    # Child staging_dir inside source_app_dir must also be rejected
    with pytest.raises(
        ValueError, match="staging_dir must be separate from source_app_dir"
    ):
        prepare_passport_push(
            staging_dir=bundle / "passport",
            source_app_dir=bundle,
            target_project_id="tgt-proj",
        )

    # Unused toolsetTool wrapper must NOT keep an orphan toolset from being pruned on push
    _w(
        bundle / "tools/dead_wrapper/dead_wrapper.json",
        {
            "displayName": "dead_wrapper",
            "toolsetTool": {"toolset": "OrphanWrappedMcp", "toolId": "op"},
        },
    )
    _w(
        bundle / "toolsets/OrphanWrappedMcp/OrphanWrappedMcp.json",
        {
            "displayName": "OrphanWrappedMcp",
            "mcpToolset": {"serverAddress": "https://orphan.run.app/mcp"},
        },
    )
    stg = _stage(bundle, tmp_path / "stg_prune")
    rep_prune = prepare_passport_push(
        staging_dir=stg,
        source_app_dir=bundle,
        target_project_id="tgt-proj",
        target_location="us",
    )
    assert "OrphanWrappedMcp" in rep_prune["pruned_orphans"]
    assert not (stg / "toolsets/OrphanWrappedMcp").exists()

    # Absolute and ../ escaping callback/instruction paths never crash strict_gates=False and fail gates
    bad_app = tmp_path / "sub" / "bad_app"
    shutil.copytree(bundle, bad_app)
    root_json = bad_app / "agents/Root_Agent/Root_Agent.json"
    rdata = json.loads(root_json.read_text(encoding="utf-8"))
    rdata["instruction"] = "../../outside.txt"
    rdata["beforeAgentCallbacks"] = [
        {"pythonCode": "/etc/hosts"},
        {"pythonCode": "../../outside.py"},
    ]
    root_json.write_text(json.dumps(rdata), encoding="utf-8")

    inv = verify_passport_invariants(bad_app, strict_gates=False)
    assert inv["fatal_passed"] is False
    assert inv["gates"]["gate_3"]["passed"] is False
    assert inv["gates"]["gate_4"]["passed"] is False
    assert any("/etc/hosts" in e for e in inv["errors"])
    assert any("../../outside.py" in e for e in inv["errors"])
    assert any("../../outside.txt" in e for e in inv["errors"])
