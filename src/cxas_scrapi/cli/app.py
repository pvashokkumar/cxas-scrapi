"""CLI subcommands for managing CXAS Apps."""

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

import argparse
import contextlib
import io
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cxas_scrapi.core.apps import Apps
from cxas_scrapi.core.common import Common
from cxas_scrapi.core.versions import Versions
from cxas_scrapi.utils.env_vars import (
    collect_env_var_declaration_names,
    extract_env_variable_defaults,
    preserve_env_var_placeholders_on_pull,
    resolve_app_env_variables_in_dir,
)

logger = logging.getLogger(__name__)


def _find_app_in_list_by_id(
    apps_client: Apps,
    app_id: str,
    project_id: str,
    location: str,
) -> Any | None:
    """Best-effort lookup of an app in list_apps() by bare app_id."""
    expected_full = f"projects/{project_id}/locations/{location}/apps/{app_id}"
    suffix = f"/apps/{app_id}"
    try:
        for candidate in list(apps_client.list_apps() or []):
            cand_name = getattr(candidate, "name", None)
            if isinstance(cand_name, str) and (
                cand_name in (expected_full, app_id)
                or cand_name.endswith(suffix)
            ):
                return candidate
    except Exception:
        return None
    return None


def _resolve_app_args(
    app_identifier: str, args: argparse.Namespace
) -> tuple[Apps, str, str]:
    """Resolves project, location, Apps client, app_name, and display_name."""
    project_id = (
        Common._get_project_id(app_identifier)
        if Common._get_project_id(app_identifier)
        else getattr(args, "project_id", None)
    )
    location = (
        Common._get_location(app_identifier)
        if Common._get_location(app_identifier)
        else getattr(args, "location", None)
    )

    if not project_id or not location:
        print(
            "Error: Could not determine project_id or location. Provide "
            "--project_id and --location if using a display name."
        )
        sys.exit(1)

    apps_client = Apps(project_id=project_id, location=location)
    app_name = app_identifier
    display_name = app_identifier

    if "projects/" not in app_identifier:
        app = apps_client.get_app_by_display_name(app_identifier)
        if app:
            app_name = app.name
            display_name = app.display_name
        else:
            matched_by_id = _find_app_in_list_by_id(
                apps_client, app_identifier, project_id, location
            )
            if matched_by_id is not None:
                app_name = matched_by_id.name
                disp = getattr(matched_by_id, "display_name", None)
                display_name = (
                    disp if isinstance(disp, str) and disp else app_identifier
                )
            else:
                print(f"App '{app_identifier}' not found.")
                sys.exit(1)

    return apps_client, app_name, display_name


def _handle_import_result(result: Any, success_verb: str) -> str | None:
    """Helper to wait for import LRO and report the outcome.

    The server excludes any resource that fails validation from the imported
    app and records the reason in ``ImportAppResponse.warnings``. Those
    messages are the only indication that part of the import did not land, so
    they are reported on stderr and treated as a failure rather than being
    discarded behind a success message.
    """
    if hasattr(result, "result"):
        print("Waiting for import to complete...")
        app = result.result()
    else:
        app = result

    app_name = getattr(app, "name", None)
    warnings = list(getattr(app, "warnings", None) or [])

    if warnings:
        print(
            f"ERROR: {len(warnings)} resource(s) were rejected by the server "
            "and are not present in the imported app:",
            file=sys.stderr,
        )
        for warning in warnings:
            print(f"  - {warning}", file=sys.stderr)
        print(
            "Fix the reported resources and push again.",
            file=sys.stderr,
        )
        sys.exit(1)

    if app_name:
        print(f"Successfully {success_verb}: {app_name}")
    else:
        print(f"Successfully {success_verb}.")
    return app_name


_CES_ROOT_ITEMS = {
    "app.yaml",
    "app.json",
    "global_instruction.txt",
    "environment.json",
    "agents",
    "tools",
    "examples",
    "guardrails",
    "toolsets",
    "evaluations",
    "evaluationDatasets",
    "evaluationExpectations",
    ".github",
}


def _has_passport_manifest(app_dir: str) -> bool:
    """True if app_dir holds passport/manifest.json."""
    return os.path.isfile(os.path.join(app_dir, "passport", "manifest.json"))


def _resolve_extracted_app_root(
    target_dir: str, export_members: list[str]
) -> str:
    """Resolve the extracted app root directory inside target_dir."""
    if export_members:
        top_components = {
            m.split("/")[0] for m in export_members if m and m.split("/")[0]
        }
        if top_components & _CES_ROOT_ITEMS:
            return target_dir
        first_top = export_members[0].split("/")[0]
        candidate = os.path.join(target_dir, first_top)
        if os.path.isdir(candidate):
            return candidate
    if os.path.exists(os.path.join(target_dir, "app.json")) or os.path.exists(
        os.path.join(target_dir, "app.yaml")
    ):
        return target_dir
    if os.path.isdir(target_dir):
        for entry in sorted(os.listdir(target_dir)):
            sub = os.path.join(target_dir, entry)
            if os.path.isdir(sub) and (
                os.path.exists(os.path.join(sub, "app.json"))
                or os.path.exists(os.path.join(sub, "app.yaml"))
            ):
                return sub
    return target_dir


def _format_pruned(pruned: Any) -> str:
    """Format pruned orphan toolset names for CLI summaries."""
    if not isinstance(pruned, list):
        return str(pruned or 0)
    names = [
        item.get("name", str(item)) if isinstance(item, dict) else str(item)
        for item in pruned
    ]
    return f"{len(names)} ({', '.join(names)})" if names else "0"


def _print_passport_export_summary(
    app_root: str, report: dict[str, Any] | None
) -> None:
    """Print a clean summary of CXAS Passport export results."""
    from cxas_scrapi.utils.passport.term_style import (  # noqa: PLC0415
        color_enabled,
        format_duration_ms,
        paint,
        plural_noun,
    )

    report = report or {}
    pruned_str = _format_pruned(report.get("pruned_orphans") or [])
    param_files = report.get("parameterized_files") or []
    param_count = (
        len(param_files)
        if isinstance(param_files, (list, dict, set))
        else int(param_files or 0)
    )

    placeholders_doc = os.path.join(app_root, "PLACEHOLDERS.md")
    passport_dir = str(
        report.get("passport_dir") or os.path.join(app_root, "passport")
    )

    services = report.get("services_discovered")
    if isinstance(services, dict):
        service_items = [
            f"{k} ({v})"
            if isinstance(v, int | str) and not isinstance(v, bool)
            else str(k)
            for k, v in services.items()
            if v
        ]
    elif isinstance(services, list | tuple | set):
        service_items = [str(s) for s in services if s]
    else:
        service_items = []

    print(
        "\n======================================================================"
    )
    print("  CXAS Passport bundle exported:")
    print(
        "======================================================================"
    )
    print(f"  App root:            {app_root}")
    print(f"  Pruned orphans:      {pruned_str}")
    print(f"  Parameterized files: {param_count}")
    placeholders = report.get("placeholders")
    if isinstance(placeholders, list) and placeholders:
        print(
            "  Placeholders:        "
            + ", ".join(f"${{{p}}}" for p in placeholders)
        )
    print(f"  Placeholder guide:   {placeholders_doc}")
    print(f"  Passport folder:     {passport_dir.rstrip(os.sep)}/")

    resources = report.get("resources") or []
    grouped: dict[tuple[str, str], list[str]] = {}
    for res in resources:
        if not isinstance(res, dict):
            continue
        service = res.get("service")
        noun = res.get("noun") or "resource"
        kind = str(res.get("kind") or "")
        if not service:
            if "bigquery" in kind:
                service, noun = "BigQuery", "dataset"
            elif "run" in kind:
                service, noun = "Cloud Run", "service"
            elif "storage" in kind:
                service, noun = "Cloud Storage", "bucket"
            elif "function" in kind:
                service, noun = "Cloud Functions", "function"
            elif "secret" in kind:
                service, noun = "Secret Manager", "secret"
            elif "discoveryengine" in kind:
                service, noun = "Vertex AI Search", "data store"
            elif "iam" in kind:
                service, noun = "IAM", "service account"
            else:
                service, noun = kind.split(".", 1)[0].title(), "resource"

        name = str(res.get("name") or res.get("id") or "").strip()
        if kind == "storage.bucket" and not name.startswith("gs://"):
            name = f"gs://{name}"
        if name:
            grouped.setdefault((service, noun), []).append(name)

    if grouped:
        total_resources = sum(len(items) for items in grouped.values())
        print(f"\n  Discovered Attached Resources ({total_resources}):")
        for (service, noun), items in grouped.items():
            count = len(items)
            print(f"    • {service} ({count} {plural_noun(noun, count)})")
            for item in items:
                print(f"        - {item}")
        print()
    elif service_items:
        print(f"  Services discovered: {', '.join(service_items)}")
    else:
        print("  Services discovered: none")

    color = color_enabled()
    not_readable = report.get("not_readable")
    if isinstance(not_readable, list) and not_readable:
        print(
            f"  {paint('WARNING', 'yellow', color)} not readable: "
            f"{len(not_readable)} resource(s), listed at "
            "the top of PLACEHOLDERS.md (exit 0; --strict fails instead)"
        )
        for item in not_readable:
            if isinstance(item, dict):
                what = item.get("what")
                part = f" ({what})" if what and what != "the resource" else ""
                print(
                    f"    - {item.get('id')}{part}: {item.get('error')}"
                    f" (missing: {item.get('missing_permission') or 'unknown'})"
                )
    errors = report.get("gcp_introspection_errors")
    if isinstance(errors, list) and errors:
        print(
            f"  {paint('Problems:', 'yellow', color)}            "
            f"{len(errors)} (also listed in PLACEHOLDERS.md)"
        )
        for err in errors[:5]:
            print(f"    - {err}")
    per_plugin = report.get("timings_per_plugin_ms")
    if isinstance(per_plugin, dict) and per_plugin:
        timings_str = ", ".join(
            f"{k.split('.')[-1]} {format_duration_ms(v)}"
            for k, v in per_plugin.items()
        )
        print(f"  GCP reads by kind:   {timings_str}")

    print("\nNext step:")
    print("  Review PLACEHOLDERS.md and deploy with:")
    print("  cxas push --passport --project-id <TARGET_PROJECT>\n")


def _can_encode_text(console: Any, text: str) -> bool:
    """Return True if console encoding can represent all glyphs in `text`."""
    encoding = getattr(console, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


@contextlib.contextmanager
def _passport_progress(description: str) -> Iterator[None]:
    """Render and retain a square spinner and progress bar on interactive TTYs."""
    from rich.console import Console  # noqa: PLC0415
    from rich.progress import (  # noqa: PLC0415
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    console = Console()
    if console.is_terminal and not console.is_dumb_terminal:
        if _can_encode_text(console, "✓◰◳◲◱━"):
            columns = (
                SpinnerColumn(
                    "squareCorners",
                    style="cyan",
                    finished_text="[bold green]✓[/bold green]",
                ),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=24),
                TimeElapsedColumn(),
            )
        else:
            columns = (
                SpinnerColumn("line", finished_text="+"),
                TextColumn("{task.description}"),
                TimeElapsedColumn(),
            )
        with Progress(
            *columns,
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(description, total=None)
            try:
                yield
            except BaseException:
                if task_id in progress.task_ids:
                    progress.update(
                        task_id, description=f"{description} (failed)"
                    )
                raise
            if task_id in progress.task_ids:
                progress.update(task_id, total=1, completed=1)
    else:
        print(description, flush=True)
        yield


def _print_passport_push_summary(
    *,
    source_app_dir: str,
    app_name: str | None,
    target_project_id: str | None,
    target_location: str | None,
    stamp_report: dict[str, Any] | None,
    check: dict[str, Any],
    skip_gates: bool,
) -> None:
    """Print a clean summary of CXAS Passport push results matching pull."""
    stamp_report = stamp_report or {}
    pruned_str = _format_pruned(stamp_report.get("pruned_orphans") or [])

    stamped_count = int(stamp_report.get("stamped_files_count", 0) or 0)
    if stamp_report.get("gates_passed", True):
        gates_str, gates_style = "PASSED", "green"
    elif stamp_report.get("fatal_passed", True):
        gates_str, gates_style = "PASSED (with warnings)", "yellow"
    elif skip_gates:
        gates_str, gates_style = "SKIPPED (--skip-passport-gates)", "yellow"
    else:
        gates_str, gates_style = "FAILED", "red"

    invariant_report = stamp_report.get("invariant_report")
    gate_errors = (
        list(invariant_report.get("errors") or [])
        if isinstance(invariant_report, dict)
        else []
    )
    gate_warnings = (
        list(invariant_report.get("warnings") or [])
        if isinstance(invariant_report, dict)
        else []
    )

    warnings = list(check.get("warnings") or [])
    problems = list(check.get("problems") or [])
    if problems:
        read_back = (
            "FAILED",
            " — the app read back from CES lacks what was uploaded",
        )
    elif check.get("checked"):
        read_back = (
            "PASSED",
            " — the app read back from CES has the uploaded model, "
            "toolsets, tools and agent bindings.",
        )
    elif warnings:
        read_back = ("SKIPPED", f" ({'; '.join(warnings)})")
    else:
        read_back = ("SKIPPED", "")

    from cxas_scrapi.utils.passport.term_style import (  # noqa: PLC0415
        color_enabled,
        paint,
        status_style,
    )

    color = color_enabled()
    read_back_str = (
        paint(read_back[0], status_style(read_back[0]), color) + read_back[1]
    )

    print(
        "\n======================================================================"
    )
    print("  CXAS Passport bundle pushed:")
    print(
        "======================================================================"
    )
    print(f"  App root:            {source_app_dir}")
    print(f"  Target app:          {app_name or '-'}")
    print(
        f"  Target project:      {target_project_id or '-'} ({target_location or '-'})"
    )
    print(f"  Pruned orphans:      {pruned_str}")
    print(f"  Stamped files:       {stamped_count}")
    print(f"  Pre-push gates:      {paint(gates_str, gates_style, color)}")
    for err in gate_errors:
        print(f"    - {paint('ERROR:', 'red', color)} {err}")
    for warn in gate_warnings:
        print(f"    - {paint('WARN:', 'yellow', color)}  {warn}")
    print(f"  CES read-back:       {read_back_str}")
    for warning in warnings:
        print(f"  Passport check:      {warning}")
    if problems:
        print(f"  {paint('Read-back issues:', 'red', color)}")
        for problem in problems:
            print(f"    - {problem}")


def _parse_set_values(items: list[str] | None) -> dict[str, str]:
    """`--set NAME=VALUE` items as {NAME: VALUE}; NAME may be written as ${NAME}."""
    values: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            print(f"Error: --set expects NAME=VALUE, got {item!r}")
            sys.exit(1)
        name, value = item.split("=", 1)
        name = name.strip()
        if name.startswith("${") and name.endswith("}"):
            name = name[2:-1]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            print(
                f"Error: --set {name!r} is not a placeholder name "
                "(upper case letters, digits and _, e.g. GCS_BUCKET_KB)"
            )
            sys.exit(1)
        values[name] = value
    return values


def app_pull(args: argparse.Namespace) -> None:
    """Handles the 'pull' command."""
    print(f"Pulling app: {args.app}")

    apps_client, app_name, _ = _resolve_app_args(args.app, args)

    version_id = getattr(args, "version_id", None)
    app_version = None
    if version_id:
        versions_client = Versions(app_name=app_name)
        try:
            app_version = versions_client.resolve_version_name(version_id)
        except ValueError as e:
            print(f"Error resolving version: {e}")
            sys.exit(1)

    passport = bool(getattr(args, "passport", False))
    live_introspect = not getattr(args, "no_live_introspect", False)
    app_dir_name = getattr(args, "app_dir_name", None)
    if passport:
        _app_pull(
            apps_client,
            app_name,
            args.target_dir,
            getattr(args, "overwrite", False),
            app_version=app_version,
            app_dir_name=app_dir_name,
            passport=passport,
            live_introspect=live_introspect,
            project_id=getattr(args, "project_id", None),
            location=getattr(args, "location", None),
            strict=bool(getattr(args, "strict", False)),
        )
    else:
        _app_pull(
            apps_client,
            app_name,
            args.target_dir,
            getattr(args, "overwrite", False),
            app_version=app_version,
            app_dir_name=app_dir_name,
        )


def _app_pull(
    apps_client: Apps,
    app_name: str,
    target_dir: str,
    overwrite: bool = False,
    app_version: str | None = None,
    app_dir_name: str | None = None,
    passport: bool = False,
    live_introspect: bool = True,
    project_id: str | None = None,
    location: str | None = None,
    strict: bool = False,
) -> dict[str, Any] | None:
    """Helper to pull an app from CXAS."""
    try:
        t_pull_start = time.perf_counter()
        dest_app_root: str | None = None
        if app_dir_name is not None:
            stripped_dir_name = app_dir_name.strip()
            if not stripped_dir_name:
                raise ValueError("--app-dir-name cannot be empty.")
            abs_target = os.path.abspath(target_dir)
            abs_dest = os.path.abspath(
                os.path.join(target_dir, stripped_dir_name)
            )
            if (
                os.path.isabs(stripped_dir_name)
                or os.path.commonpath([abs_target, abs_dest]) != abs_target
            ):
                raise ValueError(
                    f"Invalid --app-dir-name '{app_dir_name}': must be a "
                    "relative path within --target-dir."
                )
            dest_app_root = os.path.normpath(
                os.path.join(target_dir, stripped_dir_name)
            )

        # Export the app
        print("Exporting app from CXAS...")
        lro = apps_client.export_app(app_name=app_name, app_version=app_version)
        response = lro.result()

        # Determine the target directory
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        # Extract content to target directory.
        top_dir = ""
        with zipfile.ZipFile(io.BytesIO(response.app_content)) as z:
            export_members = list(z.namelist())
            if export_members:
                first_part = export_members[0].split("/")[0]
                has_top_dir = (
                    bool(first_part)
                    and any("/" in m for m in export_members)
                    and all(
                        m == first_part or m.startswith(first_part + "/")
                        for m in export_members
                    )
                )
                top_dir = first_part if has_top_dir else ""

            pulled_app_root = (
                dest_app_root
                if dest_app_root is not None
                else (
                    os.path.join(target_dir, top_dir) if top_dir else target_dir
                )
            )
            prev_env_vars = collect_env_var_declaration_names(pulled_app_root)
            prev_env_defaults: dict[str, Any] = {}
            prev_env_path = os.path.join(pulled_app_root, "environment.json")
            if prev_env_vars and os.path.isfile(prev_env_path):
                try:
                    with open(prev_env_path, encoding="utf-8") as ef:
                        prev_env_defaults, _ = extract_env_variable_defaults(
                            json.load(ef)
                        )
                except (OSError, ValueError):
                    prev_env_defaults = {}

            if dest_app_root is not None:
                os.makedirs(dest_app_root, exist_ok=True)
                abs_dest_root = os.path.abspath(dest_app_root)
                prefix = f"{top_dir}/" if top_dir else ""
                for info in z.infolist():
                    rel_name = info.filename
                    if top_dir:
                        if rel_name in (top_dir, prefix):
                            continue
                        if rel_name.startswith(prefix):
                            rel_name = rel_name[len(prefix) :]
                    if not rel_name:
                        continue
                    target_member_path = os.path.abspath(
                        os.path.join(dest_app_root, rel_name)
                    )
                    if (
                        os.path.commonpath([abs_dest_root, target_member_path])
                        != abs_dest_root
                    ):
                        raise ValueError(
                            "Path traversal detected in archive entry: "
                            f"{info.filename}"
                        )
                    info.filename = rel_name
                    z.extract(info, path=dest_app_root)
            else:
                z.extractall(target_dir)

        # Handle overwrite logic if requested
        if overwrite and export_members:
            if dest_app_root is not None:
                app_root = dest_app_root
            else:
                top_dir = export_members[0].split("/")[0]
                app_root = os.path.join(target_dir, top_dir)

            if os.path.exists(app_root):
                # Build set of exported paths relative to app_root
                export_set = set()
                for member in export_members:
                    rel_path = (
                        os.path.relpath(member, top_dir)
                        if top_dir
                        else member.rstrip("/")
                    )
                    if rel_path and rel_path != ".":
                        export_set.add(rel_path)

                # Identify root level items in export (direct children of
                # app_root)
                export_root_items = set()
                for member in export_members:
                    if top_dir:
                        parts = member.split("/")
                        if len(parts) > 1 and parts[0] == top_dir and parts[1]:
                            export_root_items.add(parts[1])
                    else:
                        first = member.split("/")[0]
                        if first:
                            export_root_items.add(first)

                # Walk the local app root bottom-up to remove files then dirs
                for root, dirs, files in os.walk(app_root, topdown=False):
                    rel_root = os.path.relpath(root, app_root)
                    if rel_root == ".":
                        rel_root = ""

                    # Check files
                    for name in files:
                        local_rel_path = (
                            os.path.join(rel_root, name) if rel_root else name
                        )
                        parts = local_rel_path.split("/")

                        if len(parts) > 1:
                            # It's a non-root level file
                            root_item = parts[0]
                            # Only remove if it belongs to a folder that WAS in
                            # the export
                            if root_item in export_root_items:  # noqa: SIM102
                                if local_rel_path not in export_set:
                                    file_path = os.path.join(root, name)
                                    print(
                                        "Removing non-exported file: "
                                        f"{file_path}"
                                    )
                                    os.remove(file_path)

                    # Check directories (remove if empty and not in export)
                    for name in dirs:
                        local_rel_path = (
                            os.path.join(rel_root, name) if rel_root else name
                        )
                        parts = local_rel_path.split("/")

                        if len(parts) > 1:
                            root_item = parts[0]
                            if root_item in export_root_items:  # noqa: SIM102
                                if (
                                    local_rel_path not in export_set
                                    and (local_rel_path + "/") not in export_set
                                ):
                                    dir_path = os.path.join(root, name)
                                    # Only remove if it's empty (we didn't keep
                                    # any files inside it)
                                    if not os.listdir(dir_path):
                                        print(
                                            "Removing empty non-exported dir: "
                                            f"{dir_path}"
                                        )
                                        os.rmdir(dir_path)

        if prev_env_vars:
            preserved = preserve_env_var_placeholders_on_pull(
                pulled_app_root,
                prev_env_vars,
                previous_env_defaults=prev_env_defaults,
            )
            if preserved:
                print(
                    "Preserved $env_var placeholders for "
                    f"{len(preserved)} variable(s) in app config and updated "
                    "environment.json."
                )

        ces_pull_extract_ms = round(
            (time.perf_counter() - t_pull_start) * 1000.0, 3
        )
        print("Successfully pulled app.")

        if passport:
            from cxas_scrapi.utils.passport.export import (  # noqa: PLC0415
                PassportReadError,
                run_passport_export,
            )

            extracted_app_root = (
                dest_app_root
                if dest_app_root is not None
                else _resolve_extracted_app_root(target_dir, export_members)
            )
            client_proj = getattr(apps_client, "project_id", None)
            if not isinstance(client_proj, str):
                client_proj = None
            client_loc = getattr(apps_client, "location", None)
            if not isinstance(client_loc, str):
                client_loc = None

            resolved_project = project_id or client_proj
            if not resolved_project and app_name and "projects/" in app_name:
                resolved_project = Common._get_project_id(app_name)

            resolved_location = location or client_loc
            if not resolved_location and app_name and "locations/" in app_name:
                resolved_location = Common._get_location(app_name)

            export_options: dict[str, Any] = {"strict": True} if strict else {}
            strict_failure = None
            progress_msg = (
                "Introspecting GCP resources & building Passport bundle..."
                if live_introspect
                else "Building Passport bundle..."
            )
            try:
                with _passport_progress(progress_msg):
                    report = run_passport_export(
                        app_root=extracted_app_root,
                        project_id=resolved_project,
                        location=resolved_location,
                        app_name=app_name,
                        apps_client=apps_client,
                        live_introspect=live_introspect,
                        **export_options,
                    )
            except PassportReadError as exc:
                report, strict_failure = exc.report, exc
            total_pull_ms = round(
                (time.perf_counter() - t_pull_start) * 1000.0, 3
            )
            if isinstance(report, dict):
                report["pull_timings_ms"] = {
                    "ces_pull_extract_ms": ces_pull_extract_ms,
                    "passport_overhead_ms": round(
                        max(total_pull_ms - ces_pull_extract_ms, 0.0), 3
                    ),
                    "total_pull_ms": total_pull_ms,
                }
            _print_passport_export_summary(extracted_app_root, report)
            if strict_failure is not None:
                print(
                    f"Error: --strict: {strict_failure} "
                    "(the bundle was written; see PLACEHOLDERS.md)."
                )
                sys.exit(1)
            return report

        return None

    except Exception as e:
        print(f"Failed to pull app: {e}")
        sys.exit(1)


def app_push(args: argparse.Namespace) -> str | None:
    """Handles the 'push' command."""
    # We will reuse the deploy_agent logic from main.py, slightly adjusted.
    app_dir = args.app_dir if args.app_dir else "."
    print(f"Pushing app from {app_dir}...")

    target_app = getattr(args, "to", None)
    app_name_arg = getattr(args, "app_name", None)
    identifier = target_app or app_name_arg

    if identifier:
        apps_client, app_name, display_name = _resolve_app_args(
            identifier, args
        )
        print("Pushing to existing app... Overwriting if supported.")
    else:
        apps_client = Apps(project_id=args.project_id, location=args.location)
        app_name = None
        print("No target specified, using existing name if needed.")
        display_name = getattr(args, "display_name", None) or "Pushed Agent"

    return _app_push(
        app_dir=app_dir,
        apps_client=apps_client,
        target_app_name=getattr(args, "app_name", None) or app_name,
        identifier=getattr(args, "to", None) or getattr(args, "app_name", None),
        display_name=getattr(args, "display_name", None) or display_name,
        env_file=getattr(args, "env_file", None),
        args=args,
    )


def _app_push(
    app_dir: str,
    apps_client: Apps = None,
    target_app_name: str | None = None,
    identifier: str | None = None,
    display_name: str | None = None,
    env_file: str | None = None,
    args: argparse.Namespace | None = None,
) -> str | None:
    """Helper to push an app to CXAS."""
    temp_dir = tempfile.mkdtemp()
    temp_zip = tempfile.mktemp(suffix=".zip")
    inner_dir = os.path.join(temp_dir, "agent")
    os.makedirs(inner_dir)

    valid_roots = [
        "app.yaml",
        "app.json",
        "global_instruction.txt",
        "environment.json",
        "agents",
        "tools",
        "examples",
        "guardrails",
        "toolsets",
        "evaluations",
        "evaluationDatasets",
        "evaluationExpectations",
        ".github/workflows",
    ]

    copy_source_dir = app_dir
    if not os.path.exists(
        os.path.join(app_dir, "app.json")
    ) and not os.path.exists(os.path.join(app_dir, "app.yaml")):
        copy_source_dir = _resolve_extracted_app_root(app_dir, [])

    effective_source_app_dir = (
        copy_source_dir
        if copy_source_dir != app_dir and not _has_passport_manifest(app_dir)
        else app_dir
    )

    stamp_report: dict[str, Any] | None = None
    target_project_id: str | None = None
    target_location: str | None = None

    try:
        for item in valid_roots:
            src_path = os.path.join(copy_source_dir, item)
            if os.path.exists(src_path):
                dst_path = os.path.join(inner_dir, item)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                if os.path.isdir(src_path):
                    shutil.copytree(src_path, dst_path)
                else:
                    shutil.copy2(src_path, dst_path)

        # Inject explicit env_file if provided
        env_file_missing = False
        if env_file:
            if os.path.exists(env_file):
                dst_path = os.path.join(inner_dir, "environment.json")
                shutil.copy2(env_file, dst_path)
                print(
                    f"Included custom environment file "
                    f"from {env_file} as environment.json"
                )
            else:
                env_file_missing = True
                print(
                    f"Warning: Custom environment file "
                    f"'{env_file}' not found. Skipping."
                )

        from cxas_scrapi.utils.tracing.app_config import (  # noqa: PLC0415
            has_bool_env_var_placeholders,
            resolve_env_booleans_in_dir,
        )

        if env_file_missing and (
            collect_env_var_declaration_names(inner_dir)
            or has_bool_env_var_placeholders(inner_dir)
        ):
            raise FileNotFoundError(
                f"Custom environment file '{env_file}' not found; required to "
                "resolve '$env_var' placeholders"
            )

        resolved_vars = resolve_app_env_variables_in_dir(inner_dir)
        if resolved_vars:
            print(
                f"Resolved {len(resolved_vars)} '$env_var' variable "
                f"default(s) from environment.json: {', '.join(resolved_vars)}"
            )

        # Resolve boolean $env_var placeholders and boolean environment
        # overrides in the staged inner_dir before creating the zip archive.
        resolve_env_booleans_in_dir(inner_dir)

        if args and getattr(args, "passport", False):
            from cxas_scrapi.utils.passport.push import (  # noqa: PLC0415
                post_passport_push,
                prepare_passport_push,
            )

            target_project_id = getattr(args, "project_id", None)
            if (
                not target_project_id
                and target_app_name
                and "projects/" in target_app_name
            ):
                target_project_id = Common._get_project_id(target_app_name)
            if not target_project_id and apps_client is not None:
                client_proj = getattr(apps_client, "project_id", None)
                if isinstance(client_proj, str):
                    target_project_id = client_proj

            target_location = getattr(args, "location", None)
            if (
                not target_location
                and target_app_name
                and "locations/" in target_app_name
            ):
                target_location = Common._get_location(target_app_name)
            if not target_location and apps_client is not None:
                client_loc = getattr(apps_client, "location", None)
                if isinstance(client_loc, str):
                    target_location = client_loc

            preserve_display_name = getattr(args, "display_name", None)
            if (
                not preserve_display_name
                and display_name
                and not display_name.startswith("projects/")
                and display_name != "Pushed Agent"
            ):
                preserve_display_name = display_name

            placeholder_values = _parse_set_values(
                getattr(args, "set_values", None)
            )
            stamp_report = prepare_passport_push(
                staging_dir=inner_dir,
                source_app_dir=effective_source_app_dir,
                target_project_id=target_project_id,
                target_location=target_location,
                env_file=env_file,
                target_toolbox_url=getattr(args, "toolbox_url", None),
                target_moh_uri=getattr(args, "moh_uri", None),
                target_gcs_bucket=getattr(args, "gcs_bucket", None),
                preserve_display_name=preserve_display_name,
                strict_gates=not getattr(args, "skip_passport_gates", False),
                target_project_number=getattr(args, "project_number", None),
                placeholder_values=placeholder_values,
                apps_client=apps_client,
            )
            manifest_used = (
                stamp_report.get("manifest_path")
                if isinstance(stamp_report, dict)
                else None
            )
            print(
                f"Passport manifest: {manifest_used}"
                if manifest_used
                else "Passport manifest: not found (stamping from CLI flags and environment.json only)"
            )
            values = (
                stamp_report.get("placeholder_values")
                if isinstance(stamp_report, dict)
                else None
            )
            if isinstance(values, dict):
                for name, info in values.items():
                    if isinstance(info, dict):
                        print(
                            f"  ${{{name}}} = {info.get('value')} ({info.get('from')})"
                        )

        # ZIP does not support timestamps before 1980.
        # Touch files and directories in temp_dir with timestamps before 1980.
        limit_time = time.mktime((1980, 1, 1, 0, 0, 0, 0, 0, 0))
        for root, dirs, files in os.walk(temp_dir):
            for name in files:
                path = os.path.join(root, name)
                if os.path.getmtime(path) < limit_time:
                    os.utime(path, None)
            for name in dirs:
                path = os.path.join(root, name)
                if os.path.getmtime(path) < limit_time:
                    os.utime(path, None)

        # Zip the filtered agent directory
        shutil.make_archive(temp_zip.replace(".zip", ""), "zip", temp_dir)

        with open(temp_zip, "rb") as f:
            app_content = f.read()

        # If no target is specified, the SDK creates a new app with the
        # provided display_name.
        print("Uploading to CES...")

        if target_app_name:
            conflict_strategy = (
                "OVERWRITE"
                if args and getattr(args, "overwrite", False)
                else None
            )
            result = apps_client.import_app(
                app_name=target_app_name,
                app_content=app_content,
                conflict_strategy=conflict_strategy,
            )
        else:
            if (
                args
                and getattr(args, "passport", False)
                and (not display_name or display_name == "Pushed Agent")
            ):
                staged_app_json = os.path.join(inner_dir, "app.json")
                if os.path.isfile(staged_app_json):
                    with (
                        contextlib.suppress(OSError, ValueError),
                        open(staged_app_json, encoding="utf-8") as f_app,
                    ):
                        staged_app = json.load(f_app)
                        if isinstance(staged_app, dict) and staged_app.get(
                            "displayName"
                        ):
                            display_name = str(staged_app["displayName"])
            result = apps_client.import_as_new_app(
                display_name=display_name, app_content=app_content
            )
        app_name = _handle_import_result(
            result, "pushed to" if identifier else "pushed"
        )

        if args and getattr(args, "create_version", False) and app_name:
            print(f"Creating version for {app_name}...")
            versions_client = Versions(
                app_name=app_name,
                creds=apps_client.creds,
            )
            version_display_name = (
                getattr(args, "version_name", None)
                or f"import-{time.strftime('%Y%m%d%H%M%S')}"
            )
            description = getattr(args, "version_description", None)
            version = versions_client.create_version(
                display_name=version_display_name,
                description=description,
            )
            version_name = version.name
            print(
                f"Created app version: {version_name} "
                f"with display name {version_display_name}"
            )
            args.created_version_name = version_name

        if args and getattr(args, "passport", False):
            from cxas_scrapi.utils.passport.push import (  # noqa: PLC0415
                verify_pushed_app,
            )
            from cxas_scrapi.utils.passport.readiness import (  # noqa: PLC0415
                audit_target_readiness,
                format_readiness_report,
            )

            with _passport_progress("Verifying pushed app in CES..."):
                check = verify_pushed_app(apps_client, app_name, inner_dir)
                post_passport_push(
                    source_app_dir=effective_source_app_dir,
                    app_name=app_name,
                    created_version_name=getattr(
                        args, "created_version_name", None
                    ),
                    target_project_id=target_project_id,
                    target_location=target_location,
                    stamp_report=stamp_report,
                )
            check = check if isinstance(check, dict) else {}
            skip_gates = bool(getattr(args, "skip_passport_gates", False))
            resolved_params = (
                (stamp_report or {}).get("resolved_parameters") or {}
                if isinstance(stamp_report, dict)
                else {}
            )
            audit_project = target_project_id or resolved_params.get(
                "target_project_id"
            )
            effective_location = target_location or resolved_params.get(
                "target_location"
            )
            _print_passport_push_summary(
                source_app_dir=effective_source_app_dir,
                app_name=app_name,
                target_project_id=audit_project,
                target_location=effective_location,
                stamp_report=stamp_report
                if isinstance(stamp_report, dict)
                else None,
                check=check,
                skip_gates=skip_gates,
            )
            from cxas_scrapi.utils.passport.term_style import (  # noqa: PLC0415
                color_enabled,
                paint,
            )

            color = color_enabled()
            problems = check.get("problems") or []
            if problems and not skip_gates:
                print(
                    "\n"
                    + paint(
                        "Push FAILED the post-upload check "
                        "(use --skip-passport-gates to accept it).",
                        "red",
                        color,
                    )
                )
                sys.exit(1)

            has_v4_manifest = _has_passport_manifest(effective_source_app_dir)
            audit_kwargs = {
                "source_app_dir": effective_source_app_dir,
                "target_project_id": audit_project,
                "target_project_number": resolved_params.get(
                    "target_project_number"
                )
                or getattr(args, "project_number", None),
                "placeholder_values": {
                    k: v.get("value", "")
                    for k, v in (
                        (stamp_report or {}).get("placeholder_values") or {}
                    ).items()
                    if isinstance(v, dict)
                }
                if isinstance(stamp_report, dict)
                else None,
                "apps_client": apps_client,
            }
            live_audit = bool(has_v4_manifest and audit_project)
            audit_ctx = (
                _passport_progress(
                    "Auditing target project Google Cloud readiness..."
                )
                if live_audit
                else contextlib.nullcontext()
            )
            with audit_ctx:
                readiness = audit_target_readiness(**audit_kwargs)
            formatted_readiness = format_readiness_report(
                readiness, show_total_latency=not live_audit, color=color
            )
            if formatted_readiness:
                print(formatted_readiness)
            else:
                print("\nNext step:")
                print(
                    "  Test the pushed agent in CES or inspect passport/ledger.jsonl.\n"
                )
            if getattr(args, "strict", False) and not readiness.get(
                "ready", True
            ):
                print(
                    paint(
                        "Push FAILED --strict: target project is missing "
                        "required Google Cloud resources or IAM bindings.",
                        "red",
                        color,
                    )
                )
                sys.exit(1)

        return app_name

    except Exception as e:
        print(f"Failed to push app: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def app_create(args: argparse.Namespace) -> None:
    """Handles the 'create' command."""
    print(f"Creating app: {args.name}")
    apps_client = Apps(project_id=args.project_id, location=args.location)
    try:
        app = apps_client.create_app(
            app_id=args.app_id,
            display_name=args.name,
            description=args.description,
        )
        print(f"App created successfully: {app.name}")
    except Exception as e:
        print(f"Failed to create app: {e}")
        sys.exit(1)


def app_delete(args: argparse.Namespace) -> None:
    """Handles the 'delete' command."""

    app_name_arg = getattr(args, "app_name", None)

    if app_name_arg:
        print(f"Deleting App: {app_name_arg}")
        project_id = Common._get_project_id(app_name_arg)
        location = Common._get_location(app_name_arg)
        app_name = app_name_arg
    elif args.display_name and args.project_id and args.location:
        print(f"Deleting App by Display Name: {args.display_name}")
        project_id = args.project_id
        location = args.location
        app_name = None
    else:
        print(
            "Error: Must provide either --app_name OR "
            "(--display_name, --project_id, --location)"
        )
        sys.exit(1)

    if not project_id or not location:
        print("Error: Could not determine project_id or location.")
        sys.exit(1)

    apps_client = Apps(project_id=project_id, location=location)

    try:
        if not app_name:
            # Lookup by display name
            app = apps_client.get_app_by_display_name(args.display_name)
            if app:
                app_name = app.name
                print(f"Found app ID: {app_name}")
            else:
                print(
                    f"App with display name '{args.display_name}' "
                    "not found. Nothing to delete."
                )
                return

        apps_client.delete_app(app_name=app_name, force=args.force)
        print(f"Successfully deleted {app_name}")
    except Exception as e:
        print(f"Failed to delete app: {e}")
        sys.exit(1)


def app_branch(args: argparse.Namespace) -> None:
    """Handles the 'branch' command."""
    print(f"Branching from {args.source} to {args.new_name}")
    # Composite operation: pull existing, create new, push content.

    apps_client, app_name, _ = _resolve_app_args(args.source, args)
    env_file = getattr(args, "env_file", None)

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            print("Pulling source app...")
            _app_pull(apps_client, app_name, temp_dir)

            extracted_dirs = [
                d
                for d in os.listdir(temp_dir)
                if os.path.isdir(os.path.join(temp_dir, d))
            ]
            app_dir = (
                os.path.join(temp_dir, extracted_dirs[0])
                if extracted_dirs
                else temp_dir
            )

            print("Pushing branched app...")
            _app_push(
                app_dir=app_dir,
                apps_client=apps_client,
                display_name=args.new_name,
                env_file=env_file,
            )
        except Exception as e:
            print(f"Failed to branch app: {e}")
            sys.exit(1)


def apps_list(args: argparse.Namespace) -> None:
    """Handles the 'apps list' command."""
    print(f"Listing apps for project {args.project_id} in {args.location}...")
    apps_client = Apps(project_id=args.project_id, location=args.location)
    try:
        apps = apps_client.list_apps()
        if not apps:
            print("No apps found.")
            return

        # Attempt to format output using pandas if available.
        try:
            import pandas as pd  # noqa: PLC0415

            data = [
                {"Display Name": app.display_name, "Name": app.name}
                for app in apps
            ]
            df = pd.DataFrame(data)
            print("\nApps:")
            print(df.to_string(index=False))
        except ImportError:
            for app in apps:
                print(f"- {app.display_name} ({app.name})")

    except Exception as e:
        print(f"Failed to list apps: {e}")
        sys.exit(1)


def apps_get(args: argparse.Namespace) -> None:
    """Handles the 'apps get' command."""
    print(f"Getting app: {args.app}")

    apps_client, app_name, _ = _resolve_app_args(args.app, args)

    try:
        app = apps_client.get_app(app_name=app_name)
        print("\nApp Details:")
        print(f"Name: {app.name}")
        print(f"Display Name: {app.display_name}")
        print(f"Description: {getattr(app, 'description', '')}")
        print(f"Create Time: {getattr(app, 'create_time', '')}")
        print(f"Update Time: {getattr(app, 'update_time', '')}")
        # Note: could dump full JSON if needed.
    except Exception as e:
        print(f"Failed to get app details: {e}")
        sys.exit(1)


def app_lint(args: argparse.Namespace) -> None:
    """Handles the 'lint' command."""
    from cxas_scrapi.utils.linter import (  # noqa: PLC0415
        SINGLE_RESOURCE_RULES,
        Discovery,
        LintConfig,
        LintContext,
        LintReport,
        build_context,
        build_registry,
        run_rules,
    )

    registry = build_registry()

    model_override = getattr(args, "model", None)
    model_only = getattr(args, "model_only", False)

    if getattr(args, "list_rules", False):
        print("CXAS Agent Linter — Available Rules")
        print("=" * 60)
        registry.list_rules(model=model_override, model_only=model_only)
        sys.exit(0)

    json_output = getattr(args, "json_output", False)
    show_fixes = getattr(args, "fix", False)

    # Per-resource validation (--agent, --tool, etc.)
    for flag, rule_id in SINGLE_RESOURCE_RULES.items():
        resource_dir = getattr(args, flag, None)
        if not resource_dir:
            continue
        resource_path = Path(resource_dir).resolve()
        rule_obj = registry.get(rule_id)
        report = LintReport()
        context = LintContext(
            project_root=resource_path.parent,
            app_dir=resource_path.parent,
            evals_dir=resource_path.parent,
        )
        if not json_output:
            print(f"Validating {flag}: {resource_path.name}")
            print("=" * 60)
        if rule_obj is not None:
            for result in rule_obj.check(resource_path, "", context):
                report.add(result)
        report.print_and_exit(json_output, show_fixes)
        return

    # Full app lint
    project_root = Path(getattr(args, "app_dir", ".")).resolve()
    config = LintConfig.load(project_root)

    app_dir = project_root / config.app_dir
    evals_dir = project_root / config.evals_dir

    limit_agents = None
    agents_arg = getattr(args, "agents", None)
    if agents_arg:
        limit_agents = set(a.strip() for a in agents_arg.split(","))

    limit_tools = None
    tools_arg = getattr(args, "tools", None)
    if tools_arg:
        limit_tools = set(t.strip() for t in tools_arg.split(","))

    discovery = Discovery(
        app_dir,
        evals_dir,
        limit_agents=limit_agents,
        limit_tools=limit_tools,
    )

    if not discovery.app_root:
        if not json_output:
            print(f"ERROR: No app directory found under {app_dir}")
            print(
                "Ensure the directory contains app.json/app.yaml and agents/. "
                "Use --app-dir to specify the app location."
            )
        else:
            import json  # noqa: PLC0415

            print(
                json.dumps(
                    [
                        {
                            "file": str(app_dir),
                            "severity": "error",
                            "rule_id": "SETUP",
                            "message": (
                                f"No app directory found under {app_dir}"
                            ),
                        }
                    ]
                )
            )
        sys.exit(1)

    env_file_arg = getattr(args, "env_file", None)
    resolved_env_file = Path(env_file_arg).resolve() if env_file_arg else None

    context = build_context(
        project_root,
        config,
        discovery,
        model_override=model_override,
        env_file=resolved_env_file,
    )

    if not json_output:
        print(f"Linting app: {discovery.app_root.name}")
        print("=" * 60)
        if context.model:
            print(f"  Model:     {context.model}")
        agents = discovery.discover_agents()
        tools = discovery.discover_tools()
        callbacks = discovery.discover_callbacks()
        evals = discovery.discover_evals()
        print(f"  Agents:    {len(agents)}")
        print(f"  Tools:     {len(tools)}")
        print(f"  Callbacks: {len(callbacks)}")
        print(f"  Evals:     {len(evals)}")

    categories = None
    if getattr(args, "validate_only", False):
        categories = ["structure", "config", "schema"]
    elif getattr(args, "only", None):
        categories = [args.only]

    specific_rules = None
    rule_arg = getattr(args, "rule", None)
    if rule_arg:
        specific_rules = set(r.strip() for r in rule_arg.split(","))

    report = LintReport()
    run_rules(
        registry,
        config,
        context,
        discovery,
        report,
        categories=categories,
        specific_rules=specific_rules,
        model_only=model_only,
    )

    report.print_and_exit(json_output, show_fixes)


def app_init(args: argparse.Namespace) -> None:
    """Handles the 'init' command -- copies skill files."""

    target_dir = Path(getattr(args, "target_dir", ".")).resolve()
    force = getattr(args, "force", False)
    skills_root = Path(sys.prefix) / "share" / "cxas-scrapi" / "skills"

    if not skills_root.exists():
        print(f"ERROR: Bundled skills not found at {skills_root}")
        print(
            "This may happen if cxas-scrapi was installed without skill data."
        )
        sys.exit(1)

    overwrite_all = force
    copied, skipped = 0, 0

    for item in sorted(skills_root.iterdir()):
        dest = target_dir / item.name
        if dest.exists() and not overwrite_all:
            choice = _prompt_overwrite(
                item.name, getattr(args, "no_input", False)
            )
            if choice == "abort":
                print("Aborted.")
                sys.exit(0)
            elif choice == "all":
                overwrite_all = True
            elif choice == "skip":
                skipped += 1
                print(f"  Skipped: {item.name}")
                continue

        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

        copied += 1
        print(f"  Installed: {item.name}")

    print(f"\nDone. {copied} installed, {skipped} skipped.")


def _prompt_overwrite(name: str, no_input: bool = False) -> str:
    """Prompt user for overwrite decision."""
    if not sys.stdin.isatty() or no_input:
        msg = (
            f"ERROR: '{name}' already exists. "
            "Non-interactive environment detected or --no-input specified."
        )
        print(msg, file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    while True:
        choice = (
            input(
                f"  '{name}' already exists. "
                "[o]verwrite / [a]ll / [s]kip / [q]uit? "
            )
            .strip()
            .lower()
        )
        if choice in ("o", "overwrite"):
            return "yes"
        if choice in ("a", "all"):
            return "all"
        if choice in ("s", "skip"):
            return "skip"
        if choice in ("q", "quit"):
            return "abort"
