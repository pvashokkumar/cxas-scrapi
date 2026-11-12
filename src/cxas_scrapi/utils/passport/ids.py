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

"""Canonical resource names of the kinds the passport graph knows.

Ids hold raw values; a project given as the source project's number becomes
the source project ID, so the same resource always gets the same node.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import WalkContext

BQ = "bigquery.dataset"
RUN = "run.service"
BUCKET = "storage.bucket"
SECRET = "secretmanager.secret"
DATA_STORE = "discoveryengine.dataStore"
ENGINE = "discoveryengine.engine"
FUNCTION = "cloudfunctions.function"
SERVICE_ACCOUNT = "iam.serviceAccount"
REPOSITORY = "artifactregistry.repository"
GATEWAY = "apigateway.gateway"
API_CONFIG = "apigateway.apiConfig"
ENDPOINT = "external.endpoint"

_AR_IMAGE_RE = re.compile(
    r"^(?P<location>[a-z0-9-]+)-docker\.pkg\.dev/(?P<project>[^/]+)/(?P<repo>[^/]+)/"
)
_SA_PROJECT_RE = re.compile(
    r"@(?P<project>[a-z][a-z0-9-]+)\.iam\.gserviceaccount\.com$"
)
_COMPUTE_SA_RE = re.compile(
    r"^(?P<number>\d+)-compute@developer\.gserviceaccount\.com$"
)


def dataset(ctx: WalkContext, project: str | None, name: str) -> str:
    return f"projects/{ctx.project_key(project)}/datasets/{name}"


def bucket(name: str) -> str:
    return f"projects/_/buckets/{name}"


def secret(ctx: WalkContext, project: str | None, name: str) -> str:
    return f"projects/{ctx.project_key(project)}/secrets/{name}"


def run_service(
    ctx: WalkContext, project: str | None, region: str, name: str
) -> str:
    return f"projects/{ctx.project_key(project)}/locations/{region}/services/{name}"


def function(
    ctx: WalkContext, project: str | None, region: str, name: str
) -> str:
    return f"projects/{ctx.project_key(project)}/locations/{region}/functions/{name}"


def service_account_project(ctx: WalkContext, email: str) -> str | None:
    """Project of a service account from its email (None for Google-managed ones)."""
    m = _SA_PROJECT_RE.search(email)
    if m:
        return m.group("project")
    m = _COMPUTE_SA_RE.match(email)
    if m:
        return ctx.project_key(m.group("number"))
    return None


def service_account(ctx: WalkContext, email: str) -> str:
    return f"projects/{service_account_project(ctx, email) or '-'}/serviceAccounts/{email}"


def default_compute_sa(project_number: str | None) -> str | None:
    if not project_number or not project_number.isdigit():
        return None
    return f"{project_number}-compute@developer.gserviceaccount.com"


def repository_of_image(
    ctx: WalkContext, image: str | None
) -> tuple[str, str, str] | None:
    """(id, location, project) of the Artifact Registry repository of an image."""
    m = _AR_IMAGE_RE.match(image or "")
    if not m:
        return None
    project = ctx.project_key(m.group("project"))
    rid = f"projects/{project}/locations/{m.group('location')}/repositories/{m.group('repo')}"
    return rid, m.group("location"), project or ""


def data_store(name: str) -> str:
    """Data store name with the default collection made explicit."""
    if "/collections/" in name:
        return name
    return name.replace(
        "/dataStores/", "/collections/default_collection/dataStores/", 1
    )
