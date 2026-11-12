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

"""IAM of the attached resources: who holds which role, without naming people.

Bindings of service accounts, Google-managed service agents, public and
special principals are kept. People and groups (`user:`, `group:`) are only
counted: a passport travels to other teams and projects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

BQ_LEGACY_ROLES = {
    "READER": "roles/bigquery.dataViewer",
    "WRITER": "roles/bigquery.dataEditor",
    "OWNER": "roles/bigquery.dataOwner",
}
CES_AGENT_DOMAIN = "gcp-sa-ces.iam.gserviceaccount.com"
_HIDDEN_PREFIXES = ("user:", "group:", "deleted:")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Role that lets the caller read each kind of resource (for "not readable").
READ_ROLES = {
    "bigquery.dataset": "roles/bigquery.metadataViewer",
    "bigquery.table": "roles/bigquery.metadataViewer",
    "run.service": "roles/run.viewer",
    "storage.bucket": "roles/storage.bucketViewer",
    "storage.objects": "roles/storage.objectViewer",
    "secretmanager.secret": "roles/secretmanager.viewer",
    "secretmanager.payload": "roles/secretmanager.secretAccessor",
    "discoveryengine.dataStore": "roles/discoveryengine.viewer",
    "discoveryengine.engine": "roles/discoveryengine.viewer",
    "cloudfunctions.function": "roles/cloudfunctions.viewer",
    "iam.serviceAccount": "roles/iam.serviceAccountViewer",
    "project": "roles/browser",
    "project.iam": "roles/iam.securityReviewer",
    "artifactregistry.repository": "roles/artifactregistry.reader",
    "apigateway.gateway": "roles/apigateway.viewer",
    "apigateway.apiConfig": "roles/apigateway.viewer",
}
# Role that lets the caller read the IAM policy of a kind (getIamPolicy); the
# bucket viewer roles lack storage.buckets.getIamPolicy.
IAM_POLICY_ROLES = {
    "run.service": "roles/run.viewer",
    "secretmanager.secret": "roles/secretmanager.viewer",
    "cloudfunctions.function": "roles/cloudfunctions.viewer",
    "storage.bucket": "roles/iam.securityReviewer",
}


@dataclass(frozen=True)
class Binding:
    """One role of one member on one resource."""

    member: str
    role: str
    condition: str | None = None


def is_hidden_member(member: str) -> bool:
    """People and groups: counted in the passport, never named."""
    return member.startswith(_HIDDEN_PREFIXES)


def ces_service_agent_member(project_number: str | None) -> str | None:
    if not project_number:
        return None
    return f"serviceAccount:service-{project_number}@{CES_AGENT_DOMAIN}"


def policy_bindings(policy: dict[str, Any] | None) -> list[Binding]:
    """`bindings[].members` of an IAM policy as one Binding per member."""
    out: list[Binding] = []
    for binding in (policy or {}).get("bindings") or []:
        role = str(binding.get("role") or "")
        cond = binding.get("condition") or None
        cond_text = (
            str(cond.get("title") or cond.get("expression") or "condition")
            if isinstance(cond, dict)
            else None
        )
        for member in binding.get("members") or []:
            out.append(Binding(str(member), role, cond_text))
    return out


def _dataset_member(entry: dict[str, Any]) -> str | None:
    if entry.get("iamMember"):
        return str(entry["iamMember"])
    if entry.get("userByEmail"):
        email = str(entry["userByEmail"])
        kind = (
            "serviceAccount"
            if email.endswith(".gserviceaccount.com")
            else "user"
        )
        return f"{kind}:{email}"
    if entry.get("groupByEmail"):
        return f"group:{entry['groupByEmail']}"
    if entry.get("domain"):
        return f"domain:{entry['domain']}"
    if entry.get("specialGroup"):
        return f"specialGroup:{entry['specialGroup']}"
    for key in ("view", "routine", "dataset"):
        if isinstance(entry.get(key), dict):
            ref = entry[key].get("dataset", entry[key])
            parts = [
                str(ref.get(k))
                for k in ("projectId", "datasetId", "tableId", "routineId")
                if ref.get(k)
            ]
            return f"authorized{key.capitalize()}:{'.'.join(parts)}"
    return None


def dataset_bindings(dataset: dict[str, Any] | None) -> list[Binding]:
    """BigQuery dataset `access` entries as Bindings (legacy roles mapped)."""
    out: list[Binding] = []
    for entry in (dataset or {}).get("access") or []:
        member = _dataset_member(entry)
        if member:
            role = str(entry.get("role") or "")
            out.append(Binding(member, BQ_LEGACY_ROLES.get(role, role)))
    return out


def visible(bindings: list[Binding]) -> tuple[list[Binding], int]:
    """(bindings that can be named, number of people/group bindings left out)."""
    shown = [b for b in bindings if not is_hidden_member(b.member)]
    return shown, len(bindings) - len(shown)


def binding_dicts(bindings: list[Binding]) -> list[dict[str, str]]:
    out = []
    for b in sorted(bindings, key=lambda b: (b.role, b.member)):
        item = {"role": b.role, "member": b.member}
        if b.condition:
            item["condition"] = b.condition
        out.append(item)
    return out


def iam_summary(bindings: list[Binding]) -> dict[str, Any]:
    """`iam.json` content for a resource: named bindings plus a hidden count."""
    shown, hidden = visible(bindings)
    return {
        "bindings": binding_dicts(shown),
        "people_and_groups_not_listed": hidden,
    }


def redact_emails(text: str) -> str:
    """Error texts name the caller; keep service accounts, hide people."""
    return _EMAIL_RE.sub(
        lambda m: (
            m.group(0)
            if m.group(0).endswith(".gserviceaccount.com")
            else "<caller>"
        ),
        text,
    )
