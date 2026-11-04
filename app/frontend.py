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
"""Frontend pages.

The backend sends the data of most pages as a JSON ``payload`` form field
from an auto-submitting page. When ``payload_key`` is configured, the backend
also sends ``payload_jwt``, an HS256 JWT over the payload, and only the
verified token is used (:func:`_load_payload`). Without it anyone can post
such a form, so every value is treated as untrusted either way:

* URLs the page posts or navigates to must be the backend endpoint the page
  is meant for (:func:`_backend_url`, :data:`_BACKEND_PATHS`);
* wallet links must be ``scheme://...`` links whose scheme cannot run code,
  the same rule the backend applies to the credential offer URI
  (:func:`_wallet_url`);
* QR codes must be PNG data URIs (:func:`_qr_code`).

A value that fails these checks gets ``400``.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import re
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urlsplit

from flask import (
    Blueprint,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
)

import app
from app import jwt_vc_issuer_metadata, oidc_metadata
from app import CONFIGURATION

frontend = Blueprint("frontend", __name__, url_prefix="/")

logger = logging.getLogger(__name__)

#: Wallet / offer link: ``scheme://...`` with no character that could leave
#: an HTML attribute or a URL.
_WALLET_URL = re.compile(r"[a-z][a-z0-9+.\-]{0,31}://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{0,8000}")
#: Schemes that run code or read local data when a link is opened; the
#: backend refuses the same ones for the user-chosen credential offer URI.
_FORBIDDEN_WALLET_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "blob", "about"})
_QR_PREFIX = "data:image/png;base64,"
#: Attributes shown as images on the consent page when the backend does not
#: send ``image_attributes`` (its ``IMAGE_ATTRIBUTES``).
_DEFAULT_IMAGE_ATTRIBUTES = (
    "portrait",
    "picture",
    "image",
    "signature_usual_mark",
    "signature_usual_mark_issuing_officer",
    "issuing_authority_logo",
)
_BASE64 = re.compile(r"[A-Za-z0-9+/=]*")

#: Backend endpoint(s) each page's URLs may point to, relative to
#: ``backend_url``; from the backend's ``redirect_url`` values and the paths
#: the templates append to them.
_BACKEND_PATHS = {
    # auth_method.html appends "dynamic/auth_method".
    "display_auth_method": ("/",),
    "display_form": ("/dynamic/form", "/preauth_form"),
    "display_authorization": ("/dynamic/redirect_wallet", "/form_authorize_generate"),
    # credential_offer.html appends "/credential_offer".
    "display_credential_offer": ("/",),
    "display_revocation_choice": ("/revocation/oid4vp_call",),
    # revocation_qr_code.html appends "pid_authorization" and "revocation/getoid4vp".
    "display_revocation_qr_code": ("/",),
    "display_revocation_authorization": ("/revocation/revoke",),
    "revocation_choice_url": ("/revocation/revocation_choice",),
}

#: ``payload_jwt``: maximum lifetime and age (seconds), and allowed clock skew.
PAYLOAD_JWT_MAX_AGE = 300
PAYLOAD_JWT_LEEWAY = 60
_JWS_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
#: Session id as logged: the backend uses UUIDs; anything else is not echoed.
_SESSION_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class InvalidPayload(ValueError):
    """Raised when a payload value fails validation."""


class UnauthenticatedPayload(InvalidPayload):
    """Raised when ``payload_jwt`` is required but missing or invalid."""


def _load_payload() -> Dict[str, Any]:
    """Reads the page payload.

    With ``payload_key`` configured it is the ``payload`` claim of the
    verified ``payload_jwt`` field (the plain ``payload`` field is ignored);
    otherwise the JSON ``payload`` form field.

    Returns:
        The decoded payload.

    Raises:
        UnauthenticatedPayload: If ``payload_jwt`` is required and fails
            :func:`_verify_payload_jwt`.
        InvalidPayload: If it is missing or not a JSON object.
    """
    if CONFIGURATION.get("payload_key"):
        payload = _verify_payload_jwt(request.form.get("payload_jwt"))
    else:
        raw = request.form.get("payload")
        if not raw:
            raise InvalidPayload("Payload not found")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidPayload("Invalid JSON payload") from e
        if not isinstance(payload, dict):
            raise InvalidPayload("Invalid JSON payload")
    _log_session(payload)
    return payload


def _log_session(payload: Dict[str, Any]) -> None:
    """Logs the page with the payload's ``session_id``, as the backend and
    authorization server tag their logs, so an issuance can be followed
    across the components. Pages without a session (credential offer,
    revocation) are not logged.
    """
    session_id = payload.get("session_id")
    if session_id is None:
        return
    if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
        session_id = "<invalid>"
    logger.info(", Session ID: %s, Page: %s", session_id, _route())


def _verify_payload_jwt(token: Optional[str]) -> Dict[str, Any]:
    """Verifies the backend's ``payload_jwt`` and returns its payload.

    The token is a compact JWS signed with HS256 under the UTF-8 bytes of
    ``payload_key``, with claims ``payload``, ``aud`` (this frontend's
    ``frontend_id``), ``iat`` and ``exp`` (at most
    :data:`PAYLOAD_JWT_MAX_AGE` after ``iat``).

    Args:
        token: The ``payload_jwt`` form field.

    Returns:
        The ``payload`` claim.

    Raises:
        UnauthenticatedPayload: If the token is missing, malformed, not
            HS256, wrongly signed, for another audience, expired, too old or
            issued in the future, or its ``payload`` is not an object.
    """
    if not isinstance(token, str):
        raise UnauthenticatedPayload("Payload token not found")
    segments = token.split(".")
    if len(segments) != 3 or not all(_JWS_SEGMENT.fullmatch(segment) for segment in segments):
        raise UnauthenticatedPayload("Malformed payload token")
    header_b64, claims_b64, signature_b64 = segments
    try:
        header = json.loads(_b64url_decode(header_b64))
        signature = _b64url_decode(signature_b64)
    except ValueError as e:
        raise UnauthenticatedPayload("Malformed payload token") from e
    # Only HS256: never "none" or an algorithm chosen by the token.
    if not isinstance(header, dict) or header.get("alg") != "HS256" or "crit" in header:
        raise UnauthenticatedPayload("Payload token algorithm not accepted")

    expected = hmac.new(
        CONFIGURATION["payload_key"].encode("utf-8"), f"{header_b64}.{claims_b64}".encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, signature):
        raise UnauthenticatedPayload("Invalid payload token signature")

    try:
        claims = json.loads(_b64url_decode(claims_b64))
    except ValueError as e:
        raise UnauthenticatedPayload("Malformed payload token") from e
    if not isinstance(claims, dict) or claims.get("aud") != CONFIGURATION["frontend_id"]:
        raise UnauthenticatedPayload("Payload token is not for this frontend")
    iat, exp = claims.get("iat"), claims.get("exp")
    if not (_is_time(iat) and _is_time(exp)):
        raise UnauthenticatedPayload("Payload token without valid iat / exp")
    now = time.time()
    if (
        exp <= now - PAYLOAD_JWT_LEEWAY
        or iat > now + PAYLOAD_JWT_LEEWAY
        or iat < now - PAYLOAD_JWT_MAX_AGE - PAYLOAD_JWT_LEEWAY
        or exp - iat > PAYLOAD_JWT_MAX_AGE
    ):
        raise UnauthenticatedPayload("Payload token expired or not yet valid")

    payload = claims.get("payload")
    if not isinstance(payload, dict):
        raise UnauthenticatedPayload("Payload token without a payload object")
    return payload


def _b64url_decode(segment: str) -> bytes:
    """Decodes an unpadded base64url JWS segment."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _is_time(value: Any) -> bool:
    """Whether a claim is a finite NumericDate (``bool`` and NaN excluded)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _backend_url(value: Optional[str], page: str) -> str:
    """Accepts a URL only when it is the backend endpoint a page is meant for.

    Args:
        value: URL from the payload.
        page: Key of :data:`_BACKEND_PATHS` (usually the route name).

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it is not an http(s) URL on the origin of
            ``backend_url`` (or of an entry in ``backend_origins``), or its
            path is not one of the page's paths under ``backend_url`` (or it
            has a query or fragment).
    """
    if not isinstance(value, str) or urlsplit(value).scheme not in ("http", "https") or _origin(value) not in _backend_origins():
        raise InvalidPayload("URL is not on the backend")
    parts = urlsplit(value)
    base_path = urlsplit(CONFIGURATION["backend_url"]).path.rstrip("/")
    if parts.query or parts.fragment or parts.path not in {base_path + path for path in _BACKEND_PATHS[page]}:
        raise InvalidPayload("URL is not the backend endpoint of this page")
    return value


def _backend_origins() -> set:
    """Returns the origins of ``backend_url`` and ``backend_origins``."""
    return {_origin(url) for url in [CONFIGURATION["backend_url"], *(CONFIGURATION.get("backend_origins") or [])]}


def _origin(url: str) -> str:
    """Returns ``scheme://host[:port]`` of a URL."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _wallet_url(value: Optional[str]) -> Optional[str]:
    """Accepts a wallet link (deeplink or https).

    The credential offer URI prefix is chosen by the user on the credential
    offer page, so any scheme the backend accepts is allowed here too.

    Args:
        value: Link from the payload; ``None`` is passed through.

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it uses unsafe characters or a scheme in
            :data:`_FORBIDDEN_WALLET_SCHEMES`.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not _WALLET_URL.fullmatch(value):
        raise InvalidPayload("Invalid wallet URL")
    if value.split(":", 1)[0] in _FORBIDDEN_WALLET_SCHEMES:
        raise InvalidPayload("Invalid wallet URL")
    return value


def _qr_code(value: Optional[str]) -> Optional[str]:
    """Accepts a QR code image given as a PNG data URI.

    Args:
        value: Data URI from the payload; ``None`` is passed through.

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it is not a base64 PNG data URI.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith(_QR_PREFIX) or not _BASE64.fullmatch(value[len(_QR_PREFIX):]):
        raise InvalidPayload("Invalid QR code")
    return value


def _image_attributes(value: Any) -> Tuple[str, ...]:
    """Names of the consent page attributes shown as images.

    Args:
        value: The payload's ``image_attributes``.

    Returns:
        ``value`` if it is a list of names, else the default names.
    """
    if isinstance(value, list) and all(isinstance(name, str) for name in value):
        return tuple(value)
    return _DEFAULT_IMAGE_ATTRIBUTES


def _with_query(url: str, **params: Any) -> str:
    """Appends URL-encoded query parameters to a URL.

    Args:
        url: Base URL.
        **params: Parameters; ``None`` values are skipped.

    Returns:
        The URL with the parameters.
    """
    query = urlencode({k: v for k, v in params.items() if v is not None})
    if not query:
        return url
    return f"{url}{'&' if '?' in url else '?'}{query}"


def _route() -> str:
    """The matched route for logs; the raw path is client-controlled."""
    return request.url_rule.rule if request.url_rule else "-"


@frontend.errorhandler(InvalidPayload)
def _invalid_payload(e: InvalidPayload):
    logger.warning("Rejected %s: %s", _route(), e)
    return jsonify({"status": "error", "message": str(e)}), 400


@frontend.errorhandler(UnauthenticatedPayload)
def _unauthenticated_payload(e: UnauthenticatedPayload):
    logger.warning("Rejected %s: %s", _route(), e)
    # Generic page: nothing from the request is shown.
    page = render_template(
        "misc/500.html",
        error="The request could not be verified. Please start again from the beginning.",
        error_code="Bad Request",
    )
    return page, 400


@frontend.route("/display_auth_method", methods=["POST"])
def display_auth_method():
    payload = _load_payload()
    return render_template(
        "misc/auth_method.html",
        pid_auth=payload.get("pid_auth"),
        country_selection=payload.get("country_selection"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_auth_method"),
    )


@frontend.route("/display_countries", methods=["POST"])
def display_countries():
    payload = _load_payload()
    return render_template(
        "dynamic/dynamic-countries.html",
        countries=payload.get("countries"),
        session_id=payload.get("session_id"),
        redirect_url=CONFIGURATION["backend_url"],
    )


@frontend.route("/display_form", methods=["POST"])
def display_form():
    payload = _load_payload()
    return render_template(
        "dynamic/dynamic-form.html",
        mandatory_attributes=payload.get("mandatory_attributes"),
        optional_attributes=payload.get("optional_attributes"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_form"),
    )


@frontend.route("/display_authorization", methods=["POST"])
def display_authorization():
    payload = _load_payload()
    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=payload.get("presentation_data"),
        image_attributes=_image_attributes(payload.get("image_attributes")),
        user_id=payload.get("session_id"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_authorization"),
    )


@frontend.route("/display_pid_login", methods=["POST"])
def display_pid_login():
    payload = _load_payload()
    return render_template(
        "openid/pid_login_qr_code.html",
        url_data=_wallet_url(payload.get("deeplink_url")),
        qrcode=_qr_code(payload.get("qr_img_base64")),
        presentation_id=payload.get("transaction_id"),
        # The page polls the backend's /pid_authorization, then opens its /getpidoid4vp.
        backend_url=CONFIGURATION["backend_url"],
    )


@frontend.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():
    return redirect(
        _with_query(f"{CONFIGURATION['backend_url']}/credential_offer_choice", frontend_id=CONFIGURATION["frontend_id"])
    )


def _json_metadata(document: Dict[str, Any]):
    resp = make_response(document, 200)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@frontend.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        if "application/jwt" in request.headers.get("Accept", ""):
            if not app.signed_metadata:
                return make_response("Signed metadata not available", 406)
            resp = make_response(app.signed_metadata, 200)
            resp.headers["Content-Type"] = "application/jwt"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Cache-Control"] = "no-store"
            return resp
        return _json_metadata(oidc_metadata)

    if service == "jwt-vc-issuer":
        # SD-JWT VC issuer metadata: issuer is this frontend, the iss of its SD-JWT VCs.
        if not jwt_vc_issuer_metadata:
            return make_response("Not available", 404)
        return _json_metadata(jwt_vc_issuer_metadata)

    # RFC 8615: a well-known URI that is not defined here does not exist. The
    # authorization server metadata is served by the authorization server
    # (authorization_servers in the credential issuer metadata).
    return make_response("Not supported", 404)


@frontend.route("/internal_error", methods=["POST"])
def display_internal_error():
    payload = _load_payload()
    # The status code is fixed: a posted payload must not choose it.
    return render_template("misc/500.html", error=payload.get("error"), error_code=payload.get("error_code")), 500


@frontend.route("/display_revocation_authorization", methods=["POST"])
def display_revocation_authorization():
    payload = _load_payload()
    return render_template(
        "misc/revocation_authorization.html",
        display_list=payload.get("display_list"),
        revocation_identifier=payload.get("revocation_identifier"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_revocation_authorization"),
        # Back to this frontend's selection list (validated without the query).
        revocation_choice_url=_with_query(
            _backend_url(payload.get("revocation_choice_url"), "revocation_choice_url"),
            frontend_id=CONFIGURATION["frontend_id"],
        ),
    )


@frontend.route("/display_revocation_success", methods=["POST"])
def display_revocation_success():
    return render_template(
        "misc/revocation_success.html",
        redirect_url=CONFIGURATION["service_url"],
    )


@frontend.route("/display_credential_offer", methods=["POST"])
def display_credential_offer():
    payload = _load_payload()

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}
    for cred, credential in oidc_metadata["credential_configurations_supported"].items():
        name = credential["credential_metadata"]["display"][0]["name"]
        if credential["format"] == "dc+sd-jwt":
            credentials["sd-jwt vc format"][cred] = name
        if credential["format"] == "mso_mdoc":
            credentials["mdoc format"][cred] = name

    return render_template(
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=_backend_url(payload.get("redirect_url"), "display_credential_offer"),
        credential_offer_URI=payload.get("credential_offer_URI"),
    )


@frontend.route("/display_credential_offer_qr_code", methods=["POST"])
def display_credential_offer_qr_code():
    payload = _load_payload()

    wallet_dev = _wallet_url(payload.get("wallet_dev"))
    tx_code = payload.get("tx_code")
    code = payload.get("code")
    offer = json.dumps(payload.get("credential_offer"))
    if wallet_dev:
        if tx_code and code:
            wallet_dev = _with_query(wallet_dev, code=code, tx_code=tx_code, credential_offer=offer)
        else:
            wallet_dev = _with_query(wallet_dev, credential_offer=offer)

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev=wallet_dev,
        url_data=_wallet_url(payload.get("url_data")),
        tx_code=tx_code if tx_code and code else None,
        qrcode=_qr_code(payload.get("qrcode")),
    )


@frontend.route("/display_revocation_choice", methods=["POST"])
def display_revocation_choice():
    payload = _load_payload()
    return render_template(
        "openid/revocation_choice.html",
        cred=payload.get("cred"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_revocation_choice"),
    )


@frontend.route("/display_revocation_qr_code", methods=["POST"])
def display_revocation_qr_code():
    payload = _load_payload()
    return render_template(
        "openid/revocation_qr_code.html",
        url_data=_wallet_url(payload.get("url_data")),
        qrcode=_qr_code(payload.get("qrcode")),
        presentation_id=payload.get("presentation_id"),
        redirect_url=_backend_url(payload.get("redirect_url"), "display_revocation_qr_code"),
    )
