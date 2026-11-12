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

"""One plugin per resource kind; `default_plugins` is the registry."""

from __future__ import annotations

from cxas_scrapi.utils.passport.plugins.api_gateway import (
    ApiConfigPlugin,
    GatewayPlugin,
)
from cxas_scrapi.utils.passport.plugins.artifact_registry import (
    ArtifactRepositoryPlugin,
)
from cxas_scrapi.utils.passport.plugins.base import Plugin
from cxas_scrapi.utils.passport.plugins.bigquery import BigQueryDatasetPlugin
from cxas_scrapi.utils.passport.plugins.cloud_run import CloudRunServicePlugin
from cxas_scrapi.utils.passport.plugins.discovery_engine import (
    DataStorePlugin,
    EnginePlugin,
)
from cxas_scrapi.utils.passport.plugins.functions import CloudFunctionPlugin
from cxas_scrapi.utils.passport.plugins.generic import (
    ExternalEndpointPlugin,
    GenericPlugin,
)
from cxas_scrapi.utils.passport.plugins.secrets import SecretPlugin
from cxas_scrapi.utils.passport.plugins.service_accounts import (
    ServiceAccountPlugin,
)
from cxas_scrapi.utils.passport.plugins.storage import StorageBucketPlugin

__all__ = ["Plugin", "default_plugins", "fallback_plugin"]


def default_plugins() -> dict[str, Plugin]:
    """Kind -> plugin, in the order the bundle lists them."""
    plugins: list[Plugin] = [
        BigQueryDatasetPlugin(),
        CloudRunServicePlugin(),
        StorageBucketPlugin(),
        SecretPlugin(),
        DataStorePlugin(),
        EnginePlugin(),
        CloudFunctionPlugin(),
        GatewayPlugin(),
        ApiConfigPlugin(),
        ServiceAccountPlugin(),
        ArtifactRepositoryPlugin(),
        ExternalEndpointPlugin(),
    ]
    return {p.kind: p for p in plugins}


def fallback_plugin() -> Plugin:
    """Live config for `generic.GENERIC_KINDS`; README only for others."""
    return GenericPlugin()
