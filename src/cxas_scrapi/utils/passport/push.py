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
# ruff: noqa: E501, PLC0415

"""Import, stamping, and provenance ledger engine for `cxas push --passport`.

Provides:
1. `prepare_passport_push`: stamps target values into the staged agent files
   from `passport/manifest.json` (`${GCP_PROJECT}`, `${GCP_PROJECT_NUMBER}`,
   and `--set NAME=VALUE`), prunes orphan toolsets, and runs all 6 pre-push
   invariant gates.
2. `verify_passport_invariants`: 5-gate pre-push architectural and live-voice
   readiness verifier (re-exported from `passport.gates`).
3. `verify_pushed_app` / `compare_pushed_app`: post-upload CES read-back check
   (re-exported from `passport.verify`).
4. `post_passport_push`: appends deployment provenance to `passport/ledger.jsonl`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.agent_graph import (
    extract_agent_graph,
)
from cxas_scrapi.utils.passport.agent_graph import (
    prune_staged_orphan_toolsets as _prune_orphan_toolsets,
)
from cxas_scrapi.utils.passport.files import read_json, write_json
from cxas_scrapi.utils.passport.gates import (
    gate6_report,
    verify_passport_invariants,
)
from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PASSPORT_LEDGER_NAME,
    PASSPORT_MANIFEST_NAME,
)
from cxas_scrapi.utils.passport.stamp import (
    clean_non_ces_items,
    is_placeholder,
    normalize_enums_recursive,
    normalize_toolbox_url,
    set_logging_buckets,
    set_mcp_server_address,
    stamp_moh_uri,
    stamp_tokens,
    unresolved_tokens,
)
from cxas_scrapi.utils.passport.verify import (
    compare_pushed_app,
    verify_pushed_app,
)

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "compare_pushed_app",
    "post_passport_push",
    "prepare_passport_push",
    "resolve_project_number",
    "verify_passport_invariants",
    "verify_pushed_app",
]

PROJECT_NUMBER_IN_HOST_RE = re.compile(r"-(\d{9,15})\.")

_OVERRIDE_TOKEN_FLAGS = {
    "MCP_TOOLBOX_URL": "--toolbox-url",
    "MOH_AUDIO_URI": "--moh-uri",
    "GCS_EVAL_BUCKET": "--gcs-bucket",
}


def _load_passport_manifest(
    source_path: Path, staging_path: Path
) -> tuple[dict[str, Any], Path | None]:
    """Load `passport/manifest.json` from `source_path` or `staging_path`."""
    for base in (source_path, staging_path):
        cand = base / PASSPORT_DIR_NAME / PASSPORT_MANIFEST_NAME
        if cand.is_file():
            data = read_json(cand)
            if data:
                return data, cand
    return {}, None


def _manifest_major(manifest: dict[str, Any]) -> int:
    try:
        return int(str(manifest.get("schema_version") or "0").split(".")[0])
    except ValueError:
        return 0


def resolve_project_number(
    project_id: str | None, apps_client: Any = None
) -> str | None:
    """Number of `project_id` from Resource Manager, or None when it cannot be read."""
    if not project_id:
        return None
    from cxas_scrapi.utils.passport.gcp import (
        GcpError,
        make_live_gcp,
        remote_fetch_allowed,
    )

    if not remote_fetch_allowed(True):
        return None
    gcp = make_live_gcp(apps_client)
    if gcp is None:
        return None
    try:
        return gcp.project_number(project_id)
    except GcpError:
        return None


def post_passport_push(
    source_app_dir: str | Path,
    app_name: str | None,
    created_version_name: str | None = None,
    target_project_id: str | None = None,
    target_location: str | None = None,
    stamp_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a structured JSON line to `<source_app_dir>/passport/ledger.jsonl`."""
    source_path = Path(source_app_dir).resolve()
    ledger_path = source_path / PASSPORT_DIR_NAME / PASSPORT_LEDGER_NAME
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    gates_passed = (
        bool(stamp_report.get("gates_passed", True))
        if isinstance(stamp_report, dict)
        else True
    )
    stamped_files_count = (
        int(stamp_report.get("stamped_files_count", 0))
        if isinstance(stamp_report, dict)
        else 0
    )

    entry = {
        "timestamp": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "app_name": app_name,
        "created_version_name": created_version_name,
        "target_project_id": target_project_id,
        "target_location": target_location,
        "gates_passed": gates_passed,
        "stamped_files_count": stamped_files_count,
    }

    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return entry


def prepare_passport_push(
    staging_dir: str | Path,
    source_app_dir: str | Path,
    target_project_id: str | None = None,
    target_location: str | None = None,
    env_file: str | None = None,
    target_toolbox_url: str | None = None,
    target_moh_uri: str | None = None,
    target_gcs_bucket: str | None = None,
    preserve_display_name: str | None = None,
    strict_gates: bool = True,
    target_project_number: str | None = None,
    placeholder_values: dict[str, str] | None = None,
    apps_client: Any = None,
    project_number_resolver: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    """Stamp target values into the staged agent files and run the pre-push gates."""
    staging_path = Path(staging_dir).resolve()
    source_path = Path(source_app_dir).resolve()
    if (
        staging_path == source_path
        or source_path.is_relative_to(staging_path)
        or staging_path.is_relative_to(source_path)
    ):
        raise ValueError(
            "staging_dir must be separate from source_app_dir so source files are not deleted"
        )
    manifest, manifest_path = _load_passport_manifest(source_path, staging_path)
    if "schema_version" in manifest and _manifest_major(manifest) < 3:
        raise ValueError(
            f"Unsupported passport schema_version {manifest.get('schema_version')!r} in "
            f"{manifest_path}; re-export the bundle with `cxas pull --passport`."
        )

    resolver = project_number_resolver or (
        lambda pid: resolve_project_number(pid, apps_client)
    )
    stamped: set[str] = set()
    staging_env = staging_path / "environment.json"
    env_data: dict[str, Any] = {}
    if env_file and Path(env_file).is_file():
        env_data = read_json(Path(env_file))
        write_json(staging_env, env_data)
    elif staging_env.is_file():
        env_data = read_json(staging_env)
    env_params = (
        env_data.get("parameters")
        if isinstance(env_data.get("parameters"), dict)
        else {}
    )
    removed_non_ces = clean_non_ces_items(staging_path)

    placeholders: dict[str, Any] = (
        manifest.get("placeholders")
        if isinstance(manifest.get("placeholders"), dict)
        else {}
    )
    values: dict[str, str] = {}
    how: dict[str, str] = {}

    def _put(name: str, value: Any, source: str) -> None:
        if (
            name not in values
            and isinstance(value, str)
            and value.strip()
            and not is_placeholder(value)
        ):
            values[name] = value.strip()
            how[name] = source

    for name, value in (placeholder_values or {}).items():
        _put(name, value, "--set")
    _put("GCP_PROJECT", target_project_id, "--project-id")
    _put("GCP_PROJECT_NUMBER", target_project_number, "--project-number")
    eff_toolbox_url = normalize_toolbox_url(target_toolbox_url)
    if "GCP_PROJECT_NUMBER" not in values and eff_toolbox_url:
        m_num = PROJECT_NUMBER_IN_HOST_RE.search(eff_toolbox_url)
        if m_num:
            _put("GCP_PROJECT_NUMBER", m_num.group(1), "the --toolbox-url host")
    for name in ("GCP_PROJECT", "GCP_PROJECT_NUMBER"):
        _put(name, env_params.get(name), "environment.json parameters")
    if "GCP_PROJECT_NUMBER" not in values and values.get("GCP_PROJECT"):
        _put(
            "GCP_PROJECT_NUMBER",
            resolver(values["GCP_PROJECT"]),
            "looked up from the project ID",
        )
    run_services = ((manifest.get("resources") or {}).get("cloud_run")) or []
    for svc in run_services:
        if not isinstance(svc, dict) or not svc.get("service"):
            continue
        token = (
            "CLOUD_RUN_URL_"
            + re.sub(r"[^A-Za-z0-9]+", "_", str(svc["service"]))
            .strip("_")
            .upper()
        )
        if token in placeholders and "GCP_PROJECT_NUMBER" in values:
            _put(
                token,
                f"https://{svc['service']}-{values['GCP_PROJECT_NUMBER']}.{svc.get('region')}.run.app",
                "derived from the project number",
            )
    for name, flag_value in (
        ("MCP_TOOLBOX_URL", eff_toolbox_url),
        ("MOH_AUDIO_URI", target_moh_uri),
        ("GCS_EVAL_BUCKET", target_gcs_bucket),
    ):
        _put(name, flag_value, _OVERRIDE_TOKEN_FLAGS[name])
    for name, value in env_params.items():
        _put(str(name), value, "environment.json parameters")

    graph = extract_agent_graph(staging_path)
    agent_info = (
        manifest.get("agent") if isinstance(manifest.get("agent"), dict) else {}
    )
    prune_hints = {
        "active_toolsets": list(agent_info.get("active_toolsets") or []),
        "pruned_orphans": [
            str(p.get("name"))
            for p in agent_info.get("pruned_orphan_toolsets") or []
            if isinstance(p, dict)
        ],
    }
    pruned = _prune_orphan_toolsets(staging_path, graph, env_data, prune_hints)

    names = set(placeholders) | set(_OVERRIDE_TOKEN_FLAGS) | set(values)
    stamped |= stamp_tokens(staging_path, values, names)
    if staging_env.is_file():
        env_data = read_json(staging_env)

    if eff_toolbox_url:
        files, count = set_mcp_server_address(
            staging_path, env_data, eff_toolbox_url
        )
        stamped |= files
        if count > 1:
            print(
                f"Warning: --toolbox-url points all {count} MCP toolsets at {eff_toolbox_url}."
            )
    if target_moh_uri and not is_placeholder(target_moh_uri):
        stamped |= stamp_moh_uri(staging_path, target_moh_uri)
    if (
        target_gcs_bucket
        and not is_placeholder(target_gcs_bucket)
        and set_logging_buckets(env_data.get("app") or {}, target_gcs_bucket)
    ):
        stamped.add("environment.json")
    if env_data and (staging_env.is_file() or env_file):
        write_json(staging_env, env_data)

    app_json = staging_path / "app.json"
    if app_json.is_file():
        try:
            loaded_app = json.loads(app_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            loaded_app = None
        if isinstance(loaded_app, dict):
            before = json.dumps(loaded_app, sort_keys=True)
            app_data, _ = normalize_enums_recursive(loaded_app)
            if preserve_display_name:
                app_data["displayName"] = preserve_display_name
            if target_gcs_bucket and not is_placeholder(target_gcs_bucket):
                set_logging_buckets(app_data, target_gcs_bucket)
            if json.dumps(app_data, sort_keys=True) != before:
                write_json(app_json, app_data)
                stamped.add("app.json")
    for folder in (
        "evaluations",
        "evaluationDatasets",
        "evaluationExpectations",
    ):
        base = staging_path / folder
        if not base.is_dir():
            continue
        for ej in sorted(base.rglob("*.json")):
            data = read_json(ej)
            new_data, count = normalize_enums_recursive(data)
            if count:
                write_json(ej, new_data)
                stamped.add(str(ej.relative_to(staging_path)))

    clean_non_ces_items(staging_path)
    required = {
        name
        for name, info in placeholders.items()
        if not isinstance(info, dict) or info.get("required_for_push", True)
    } | {"GCP_PROJECT", "GCP_PROJECT_NUMBER"}
    unresolved = unresolved_tokens(staging_path, required)
    base_report = verify_passport_invariants(staging_path, strict_gates=False)
    report = gate6_report(base_report, unresolved, placeholders, strict_gates)
    return {
        "bundle_layout": str(manifest.get("bundle_layout") or "passport-v4"),
        "gates_passed": report["gates_passed"],
        "fatal_passed": report["fatal_passed"],
        "gates": report["gates"],
        "invariant_report": report,
        "stamped_files": sorted(stamped),
        "stamped_files_count": len(stamped),
        "pruned_orphans": pruned,
        "removed_non_ces_items": removed_non_ces,
        "manifest_path": str(manifest_path) if manifest_path else None,
        "placeholder_values": {
            name: {"value": values[name], "from": how[name]}
            for name in sorted(values)
        },
        "unresolved_placeholders": [
            {"file": f, "line": n, "placeholder": p} for f, n, p in unresolved
        ],
        "resolved_parameters": {
            "target_project_id": values.get("GCP_PROJECT"),
            "target_project_number": values.get("GCP_PROJECT_NUMBER"),
            "target_location": target_location,
            "target_toolbox_url": eff_toolbox_url,
            "target_moh_uri": target_moh_uri,
            "target_gcs_bucket": target_gcs_bucket,
            "preserve_display_name": preserve_display_name,
        },
    }
