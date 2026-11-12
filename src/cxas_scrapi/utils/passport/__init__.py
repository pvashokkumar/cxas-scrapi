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

"""`cxas pull --passport` and `cxas push --passport` package.

The passport export (`export.run_passport_export`) walks the Google Cloud
resources a CES agent depends on through each service's own read-only API and
writes their live metadata next to the agent files. The push engine
(`push.prepare_passport_push`, `push.verify_pushed_app`,
`push.post_passport_push`) stamps target placeholders, runs the 6 pre-push
gates, verifies the uploaded app in CES, and audits target Google Cloud
readiness (`readiness.audit_target_readiness`).
"""

from __future__ import annotations

from cxas_scrapi.utils.passport.export import (
    PassportReadError,
    run_passport_export,
)
from cxas_scrapi.utils.passport.push import (
    compare_pushed_app,
    post_passport_push,
    prepare_passport_push,
    verify_passport_invariants,
    verify_pushed_app,
)

__all__ = [
    "PassportReadError",
    "compare_pushed_app",
    "post_passport_push",
    "prepare_passport_push",
    "run_passport_export",
    "verify_passport_invariants",
    "verify_pushed_app",
]
