###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""Test application: a temporary configuration and a stubbed backend."""

import os
import sys
import tempfile
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_CONFIG_DIR = tempfile.mkdtemp(prefix="frontend-tests-")
_CONFIG_PATH = os.path.join(_CONFIG_DIR, "frontend_config.yaml")
with open(_CONFIG_PATH, "w") as f:
    f.write(
        f"""
service_url: "https://fe.test"
log_dir: "{_CONFIG_DIR}/logs/logs.log"
frontend_id: "fe1"
backend_url: "https://backend.test"
backend_api_key: "{'k' * 40}"
"""
    )
os.makedirs(os.path.join(_CONFIG_DIR, "logs"), exist_ok=True)
os.environ["ISSUER_CONFIG_PATH"] = _CONFIG_PATH

METADATA = {
    "openid_credential_issuer": {
        "credential_issuer": "https://fe.test",
        "credential_configurations_supported": {
            "pid_mdoc": {
                "format": "mso_mdoc",
                "credential_metadata": {"display": [{"name": "PID"}]},
            }
        },
    },
    "jwt_vc_issuer": {"issuer": "https://fe.test", "jwks": {"keys": [{"kty": "EC", "kid": "ds"}]}},
}


def _fake_get(url, headers=None, timeout=None, allow_redirects=True):
    response = mock.Mock(is_redirect=False)
    response.raise_for_status = lambda: None
    response.json = lambda: {"signed_metadata": "a.b.c"} if url.endswith("/signed") else METADATA
    return response


@pytest.fixture(scope="session")
def app():
    with mock.patch("requests.get", _fake_get):
        import app as app_module

        application = app_module.create_app({"TESTING": True})
    return application


@pytest.fixture
def client(app):
    return app.test_client()
