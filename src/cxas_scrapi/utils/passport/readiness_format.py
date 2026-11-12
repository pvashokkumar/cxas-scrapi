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

"""Terminal formatting for `cxas push --passport` target readiness reports."""

from __future__ import annotations

from typing import Any

from cxas_scrapi.utils.passport.term_style import (
    format_duration_ms,
    paint,
    plural_noun,
    status_style,
)

READY, MISSING, MISCONFIGURED, NOT_CHECKED = ("READY", "MISSING", "MISCONFIGURED", "NOT_CHECKED")  # fmt: skip

_KIND_META: dict[str, tuple[str, str, str]] = {
    "bigquery.dataset": ("BigQuery", "dataset", "BigQuery dataset "),
    "run.service": ("Cloud Run", "service", "Cloud Run service "),
    "cloudfunctions.function": (
        "Cloud Functions",
        "function",
        "Cloud Function ",
    ),
    "storage.bucket": ("Cloud Storage", "bucket", "Cloud Storage bucket "),
    "secretmanager.secret": (
        "Secret Manager",
        "secret",
        "Secret Manager secret ",
    ),
    "discoveryengine.dataStore": (
        "Vertex AI Search",
        "data store",
        "Vertex AI Search data store ",
    ),
    "discoveryengine.engine": (
        "Vertex AI Search",
        "engine",
        "Vertex AI Search engine ",
    ),
    "iam.serviceAccount": ("IAM", "service account", "Service account "),
    "project.iam": ("Project IAM", "check", "Project IAM policy "),
}


def _short_resource_label(kind: str, resource: str) -> str:
    meta = _KIND_META.get(kind)
    label = resource
    if meta and resource.startswith(meta[2]):
        label = resource[len(meta[2]) :]
    elif kind == "project.iam" and resource.startswith("IAM role "):
        label = resource[len("IAM role ") :]
    label = label.replace("`", "").strip()
    if kind == "storage.bucket" and label and not label.startswith("gs://"):
        return f"gs://{label}"
    return label


def format_readiness_report(
    report: dict[str, Any],
    *,
    show_total_latency: bool = True,
    color: bool = False,
) -> str:
    """The readiness report as text; `color` grades statuses with ANSI colors."""
    if not report.get("checked") or not report.get("checks"):
        return ""
    project = report.get("target_project_id") or "target"
    checks: list[dict[str, Any]] = list(report["checks"])
    summary = report.get("summary") or {}
    ready_cnt = int(
        summary.get("ready", sum(1 for c in checks if c.get("status") == READY))
    )
    missing_cnt = int(
        summary.get(
            "missing", sum(1 for c in checks if c.get("status") == MISSING)
        )
    )
    miscfg_cnt = int(
        summary.get(
            "misconfigured",
            sum(1 for c in checks if c.get("status") == MISCONFIGURED),
        )
    )
    not_checked_cnt = int(
        summary.get(
            "not_checked",
            sum(1 for c in checks if c.get("status") == NOT_CHECKED),
        )
    )

    breakdown = [f"{ready_cnt} ready"]
    if missing_cnt:
        breakdown.append(f"{missing_cnt} missing")
    if miscfg_cnt:
        breakdown.append(f"{miscfg_cnt} misconfigured")
    if not_checked_cnt:
        breakdown.append(f"{not_checked_cnt} not checked")

    lines = [
        "",
        "======================================================================",
        "  CXAS Passport target readiness:",
        "======================================================================",
        f"  Target project:      {project}",
        f"  Checks total:        {len(checks)} ({', '.join(breakdown)})",
    ]

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for c in checks:
        kind = str(c.get("kind") or "")
        meta = _KIND_META.get(kind)
        if meta:
            service, noun = meta[0], meta[1]
        else:
            service = kind.split(".", 1)[0].replace("_", " ").title() or "Other"
            noun = "resource"
        grouped.setdefault((service, noun), []).append(c)

    lines.append(f"\n  Target Resource Readiness ({len(checks)}):")
    for (service, noun), items in grouped.items():
        count = len(items)
        lines.append(f"    • {service} ({count} {plural_noun(noun, count)})")
        for c in items:
            kind = str(c.get("kind") or "")
            label = _short_resource_label(kind, str(c.get("resource") or ""))
            status = str(c.get("status") or "")
            detail = str(c.get("detail") or "")
            badge = paint(f"[{status}]", status_style(status), color)
            lines.append(f"        - {badge} {label}: {detail}")
            if c.get("remediation") and status in (MISSING, MISCONFIGURED):
                fix = f"-> {c['remediation']}"
                lines.append(f"            {paint(fix, 'cyan', color)}")

    if report.get("ready"):
        if ready_cnt == 0 and not_checked_cnt > 0:
            result_style = "yellow"
            result_line = (
                f"not verified (0 ready, {not_checked_cnt} not checked)"
            )
        elif not_checked_cnt:
            result_style = "green"
            result_line = (
                f"all attached resources Ready "
                f"({ready_cnt} ready, {not_checked_cnt} not checked)"
            )
        else:
            result_style = "green"
            result_line = f"all attached resources Ready ({ready_cnt} checked)"
    else:
        result_style = "red" if missing_cnt else "yellow"
        result_line = (
            f"{missing_cnt} missing, {miscfg_cnt} misconfigured, {ready_cnt} ready"
            + (f", {not_checked_cnt} not checked" if not_checked_cnt else "")
        )

    lines.append(
        f"\n  Result:              {paint(result_line, result_style, color)}"
    )

    latency_ms = report.get("latency_ms")
    if show_total_latency and isinstance(latency_ms, dict):
        audit_ms = latency_ms.get("total_readiness_audit_ms")
        if audit_ms is not None:
            lines.append(
                f"  Readiness latency:   {format_duration_ms(audit_ms)}"
            )
    per_kind = report.get("timings_by_kind_ms")
    if isinstance(per_kind, dict) and per_kind:
        timings_str = ", ".join(
            f"{k.removeprefix('readiness.')} {format_duration_ms(v)}"
            for k, v in per_kind.items()
        )
        lines.append(f"  GCP reads by kind:   {timings_str}")

    lines.append("\nNext step:")
    if report.get("ready"):
        if ready_cnt == 0 and not_checked_cnt > 0:
            lines.append(
                f"  Readiness checks in {project} could not be verified "
                "(see errors above). Verify target project permissions/APIs "
                "or test the agent in CES."
            )
        else:
            lines.append(
                f"  Target resources in {project} are ready. "
                "Test the agent in CES or run evals."
            )
    else:
        lines.append(
            "  Provision the missing/misconfigured items above "
            "(see PLACEHOLDERS.md), then re-verify with:"
        )
        lines.append(f"  cxas push --passport --project-id {project} --strict")
    lines.append("")
    return "\n".join(lines)
