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

"""Passport CLI color grading: colored on terminals, plain everywhere else."""

from __future__ import annotations

import io

import pytest

from cxas_scrapi.utils.passport import term_style
from cxas_scrapi.utils.passport.readiness import format_readiness_report

GREEN, RED, YELLOW, CYAN, DIM, RESET = (
    "\x1b[32m",
    "\x1b[31m",
    "\x1b[33m",
    "\x1b[36m",
    "\x1b[2m",
    "\x1b[0m",
)

_REPORT = {
    "checked": True,
    "target_project_id": "demo-tgt",
    "ready": False,
    "summary": {"ready": 1, "missing": 1, "misconfigured": 1, "not_checked": 1},
    "checks": [
        {
            "status": "READY",
            "kind": "storage.bucket",
            "resource": "Cloud Storage bucket `demo-tgt-kb`",
            "detail": "bucket present",
            "remediation": None,
        },
        {
            "status": "MISSING",
            "kind": "bigquery.dataset",
            "resource": "BigQuery dataset `orders_ds`",
            "detail": "dataset does not exist",
            "remediation": "Run: passport/bigquery/orders_ds/schema.sql",
        },
        {
            "status": "MISCONFIGURED",
            "kind": "run.service",
            "resource": "Cloud Run service `toolbox` (us-central1)",
            "detail": "custom audience missing",
            "remediation": "gcloud run services update toolbox",
        },
        {
            "status": "NOT_CHECKED",
            "kind": "secretmanager.secret",
            "resource": "Secret Manager secret `api-key`",
            "detail": "HTTP 403",
            "remediation": None,
        },
    ],
}


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(var, raising=False)


def test_colors_only_on_interactive_terminals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert term_style.color_enabled(_Tty()) is True
    assert term_style.color_enabled(io.StringIO()) is False
    monkeypatch.setenv("TERM", "dumb")
    assert term_style.color_enabled(_Tty()) is False


def test_no_color_wins_and_force_color_overrides_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert term_style.color_enabled(_Tty()) is False
    monkeypatch.delenv("NO_COLOR")
    assert term_style.color_enabled(io.StringIO()) is True
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert term_style.color_enabled(io.StringIO()) is False


def test_paint_and_status_styles() -> None:
    assert term_style.paint("READY", "green", False) == "READY"
    assert term_style.paint("READY", "green", True) == f"{GREEN}READY{RESET}"
    assert term_style.paint("READY", None, True) == "READY"
    assert term_style.status_style("READY") == "green"
    assert term_style.status_style("PASSED") == "green"
    assert term_style.status_style("MISSING") == "red"
    assert term_style.status_style("FAILED") == "red"
    assert term_style.status_style("MISCONFIGURED") == "yellow"
    assert (
        term_style.status_style("SKIPPED (--skip-passport-gates)") == "yellow"
    )
    assert term_style.status_style("NOT_CHECKED") == "dim"
    assert term_style.status_style("UNKNOWN") is None
    assert term_style.status_style("") is None


def test_readiness_report_is_plain_by_default() -> None:
    text = format_readiness_report(_REPORT)
    assert "\x1b[" not in text
    assert "- [READY] gs://demo-tgt-kb: bucket present" in text
    assert "- [MISSING] orders_ds: dataset does not exist" in text


def test_readiness_report_grades_every_status_when_colored() -> None:
    text = format_readiness_report(_REPORT, color=True)
    assert f"- {GREEN}[READY]{RESET} gs://demo-tgt-kb: bucket present" in text
    assert f"- {RED}[MISSING]{RESET} orders_ds:" in text
    assert f"- {YELLOW}[MISCONFIGURED]{RESET} toolbox (us-central1):" in text
    assert f"- {DIM}[NOT_CHECKED]{RESET} api-key:" in text
    assert (
        f"{CYAN}-> Run: passport/bigquery/orders_ds/schema.sql{RESET}" in text
    )
    assert (
        f"Result:              {RED}1 missing, 1 misconfigured, 1 ready, "
        f"1 not checked{RESET}" in text
    )


def test_ready_and_unverified_results_are_green_and_yellow() -> None:
    ready = {
        **_REPORT,
        "ready": True,
        "summary": {
            "ready": 1,
            "missing": 0,
            "misconfigured": 0,
            "not_checked": 0,
        },
        "checks": [_REPORT["checks"][0]],
    }
    assert (
        f"{GREEN}all attached resources Ready (1 checked){RESET}"
        in format_readiness_report(ready, color=True)
    )
    unverified = {
        **_REPORT,
        "ready": True,
        "summary": {
            "ready": 0,
            "missing": 0,
            "misconfigured": 0,
            "not_checked": 1,
        },
        "checks": [_REPORT["checks"][3]],
    }
    assert (
        f"{YELLOW}not verified (0 ready, 1 not checked){RESET}"
        in format_readiness_report(unverified, color=True)
    )
