# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
"""
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This __init__.py serves double duty: it will contain the application factory, and it tells Python that the flask directory should be treated as a package.
"""

import os
import sys
import logging
import secrets
import yaml
import requests

sys.path.append(os.path.dirname(__file__))

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, g, jsonify, render_template, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from typing import Dict, Any
from urllib.parse import urlencode

from app.app_config.logging_config import configure_logging

# Log

oidc_metadata: Dict[str, Any] = {}
jwt_vc_issuer_metadata: Dict[str, Any] = {}
signed_metadata: str = None


def _load_config() -> dict:
    config_path = os.environ.get(
        "ISSUER_CONFIG_PATH",
        "/etc/issuer_config/frontend_config.yaml",
    )
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if not config:
            raise RuntimeError(f"Config file is empty: {config_path}")
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in config: {e}")

    return config


CONFIGURATION = _load_config()

logger = logging.getLogger(__name__)


def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    logger.exception("- WARN - Error 500")
    # now you're handling non-HTTP exceptions only
    return (
        render_template(
            "misc/500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )


def page_not_found(e):
    # repr() escapes control characters, so the path cannot forge log lines.
    logger.warning("Error 404: %r", request.path)  # nosemgrep: log-request-data-unsanitised
    return (
        render_template(
            "misc/500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )


from typing import Optional
from urllib.parse import urlsplit


#: Script origins the templates load from, besides this frontend.
_SCRIPT_ORIGINS = ("https://webgate.ec.europa.eu",)


#: Default ``MAX_CONTENT_LENGTH`` (``max_content_length``): 1 MiB.
DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024
#: Hosts ``backend_url`` may use plain http with (local development).
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _content_security_policy(nonce: str) -> str:
    """Builds the Content-Security-Policy of a page.

    There is no ``form-action``: browsers apply it to the whole redirect chain
    of a submission, and the backend answers form posts with redirects to the
    authorization server and to country identity providers. Form targets come
    only from validated payload URLs (:mod:`app.frontend`). Inline scripts run
    only with the per-request ``nonce`` (``csp_nonce`` in templates); event
    handlers are in ``static/scripts/page-actions.js``. Templates only load
    stylesheets from this frontend.

    Args:
        nonce: Nonce of this response's inline ``<script>`` blocks.
    """
    backends = " ".join(
        sorted({_origin(url) for url in [CONFIGURATION["backend_url"], *(CONFIGURATION.get("backend_origins") or [])]})
    )
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' {' '.join(_SCRIPT_ORIGINS)}; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data: https:; "
        "img-src 'self' data:; "
        f"connect-src 'self' {backends}; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    )


def _origin(url: str) -> str:
    """Returns ``scheme://host[:port]`` of a URL."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _check_backend_url() -> None:
    """Refuses a ``backend_url`` the API key would be sent to in clear.

    Raises:
        RuntimeError: If it is not https and its host is not local.
    """
    parts = urlsplit(CONFIGURATION["backend_url"])
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS):
        raise RuntimeError("backend_url must be https (http only for localhost, 127.0.0.1 or ::1)")


def create_app(test_config=None):
    # No CSRF protection, by design (SonarCloud S4502 reviewed as safe): there
    # is no cookie, session or SECRET_KEY, so a cross-site request carries no
    # credentials. The POST routes render pages from what is posted (the
    # backend's auto-submitting pages post to them from another origin; the
    # data is authenticated by payload_key).
    app = Flask(__name__, instance_relative_config=True)  # NOSONAR - CSRF not applicable, see above
    app.config["MAX_CONTENT_LENGTH"] = int(CONFIGURATION.get("max_content_length", DEFAULT_MAX_CONTENT_LENGTH))

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    configure_logging(app, CONFIGURATION)

    app.logger.info("Running initialization setups...")
    _check_backend_url()
    if not CONFIGURATION.get("payload_key"):
        logger.warning(
            "payload_key is not configured: display payloads are unauthenticated (anyone can post them to /display_*)"
        )
    setup_metadata()

    @app.route("/", methods=["GET"])
    def initial_page():
        return render_template(
            "misc/initial_page.html",
            oidc=f"{CONFIGURATION['service_url']}/.well-known/openid-credential-issuer",
            service_url=CONFIGURATION["service_url"],
            # The backend lists only the credentials this frontend publishes.
            revocation_url=f"{CONFIGURATION['backend_url']}/revocation/revocation_choice?"
            + urlencode({"frontend_id": CONFIGURATION["frontend_id"]}),
        )

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory("static/images", "favicon.ico")

    @app.route("/ic-logo.png")
    def logo():
        return send_from_directory("static/images", "ic-logo.png")

    if test_config is None:
        # load the instance config (in instance directory), if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # register blueprint for the /pid route
    from . import frontend

    app.register_blueprint(frontend.frontend)

    # The frontend keeps no session (no cookie, no SECRET_KEY). Only the
    # public metadata may be read cross-origin, without credentials: browser
    # based wallets and verifiers fetch it (SonarCloud S5122 reviewed as safe).
    CORS(app, resources={r"/.well-known/*": {"origins": "*"}}, supports_credentials=False, send_wildcard=True)  # NOSONAR - public metadata only, no credentials

    @app.context_processor
    def csp_nonce():
        # One nonce per request, created when a template first uses it.
        def nonce():
            if "csp_nonce" not in g:
                g.csp_nonce = secrets.token_urlsafe(16)
            return g.csp_nonce

        return {"csp_nonce": nonce}

    @app.after_request
    def add_security_headers(response):
        nonce = g.get("csp_nonce") or secrets.token_urlsafe(16)
        response.headers.setdefault("Content-Security-Policy", _content_security_policy(nonce))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    app.logger.info(" - DEBUG - FLASK started")

    return app


METADATA_TIMEOUT = 10


def _fetch_backend_metadata(path: str) -> Dict[str, Any]:
    """GETs a ``/metadata`` document of this frontend from the backend.

    Args:
        path: Path after ``/metadata/<frontend_id>`` (``""`` or ``"/signed"``).

    Returns:
        The decoded JSON body.
    """
    url = f"{CONFIGURATION['backend_url']}/metadata/{CONFIGURATION['frontend_id']}{path}"
    response = requests.get(
        url,
        headers={"X-Api-Key": CONFIGURATION["backend_api_key"]},
        timeout=METADATA_TIMEOUT,
        # A redirect could carry the API key to another host.
        allow_redirects=False,
    )
    if response.is_redirect:
        raise RuntimeError(f"Backend redirected the metadata request ({response.status_code})")
    response.raise_for_status()
    return response.json()


def setup_metadata():
    """Loads this frontend's metadata (unsigned and signed) from the backend.

    The backend builds the documents from ``frontends_config.<frontend_id>``
    (``url``, ``credentials_supported``) and the country signing keys
    (``jwt_vc_issuer``). The credential issuer metadata names the
    authorization server in ``authorization_servers``; wallets read that
    server's metadata there. The dicts are updated in place so modules that
    imported them keep a valid reference.
    """
    global signed_metadata

    try:
        documents = _fetch_backend_metadata("")
        signed = _fetch_backend_metadata("/signed").get("signed_metadata")
    except Exception:
        logger.exception("Metadata Error: unable to load metadata from the backend")
        raise

    oidc_metadata.clear()
    oidc_metadata.update(documents["openid_credential_issuer"])
    jwt_vc_issuer_metadata.clear()
    # Absent from backends that predate /.well-known/jwt-vc-issuer.
    jwt_vc_issuer_metadata.update(documents.get("jwt_vc_issuer") or {})
    signed_metadata = signed

    logger.info(
        "Metadata loaded from the backend: %d credential configurations",
        len(oidc_metadata.get("credential_configurations_supported", {})),
    )
