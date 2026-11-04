## [0.9.4]

_02 Apr 2026_

### Added
- Sign metadata support

### Changed
- Configuration to yaml
- install.md

## [0.9.5]

_05 Aug 2026_

### Added
- Forwarding additional headers in pushed authorization requests.

## [0.9.6]

_06 Oct 2026_

### Added
- `backend_api_key` configuration: sent to the backend to load this frontend's metadata.
- `backend_origins` configuration (optional): other public origins of the backend.
- Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` headers.
- Test suite (`tests/`) and a CI workflow running it.

### Changed
- Metadata is loaded from the backend (`/metadata/<frontend_id>` and `/metadata/<frontend_id>/signed`) instead of being built from local templates; `credentials_supported` and `oauth_url` for the metadata are now configured in the backend.
- Pages only post to and navigate to URLs on the backend origin, wallet links must use a scheme that cannot run code, and QR codes must be PNG data URIs: the `payload` form field can be posted by anyone.
- CORS only allows the public metadata (`/.well-known/*`), without credentials; it reflected any origin with cookies.
- The frontend keeps no session: `SECRET_KEY="dev"` and Flask-Session were removed.
- The pushed authorization proxy relays only safe upstream headers and returns generic errors.
- jQuery is served locally.
- The Docker image runs as an unprivileged user (UID 10001) and only copies `app/`.
- CI: SonarCloud runs on `pull_request` instead of `pull_request_target` and actions are pinned to commit SHAs.
- Removed unused `app/misc.py`, `app/static/jwks.json` and the local metadata templates.

### Fixed
- XSS through `javascript:` URLs in links, form actions and the revocation page's inline `onclick`.
- XSS through payload values inside `<script>` blocks (revocation and PID login pages): values are now JSON encoded.
- DOM XSS in the attribute form, where attribute names were inserted with `innerHTML`.
- `/internal_error` no longer takes its HTTP status from the posted payload.
- Raw payloads, request bodies and headers are no longer logged or printed.
- Pages use the `strict-origin` referrer policy instead of `no-referrer`: with `no-referrer` browsers send `Origin: null` on form posts, which the backend's CSRF check rejects.
- The Content-Security-Policy has no `form-action`: browsers apply it to redirects too, which blocked the backend's redirect to the authorization server after consent.

## [0.10.0]

_07 Oct 2026_

### Added
- Passthrough registration certificate from backend

## [0.11.0]

_04 Nov 2026_

### Added
- `payload_key`: the `/display_*` pages and `/internal_error` require `payload_jwt`, an HS256 JWT from the backend (`aud` = `frontend_id`, at most 300 s), instead of a plain `payload`.
- Pages posted by the backend log `, Session ID: <id>, Page: <route>`, like the other components.

### Changed
- Templates share one frame, `layout/base.html`, plus partials for the footer, credential selection and QR pages (SonarCloud duplication).
- Each page only accepts the backend endpoint it posts or links to, on top of the same-origin check.
- Wallet links on QR pages must be `scheme://` links without `javascript`, `data`, `vbscript`, `file`, `blob` or `about`, as the backend requires.
- Backend metadata requests do not follow redirects; `backend_url` must be https, except on localhost.
- The pushed authorization relay, `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` and `oauth_url` are removed: wallets use the authorization server named in `authorization_servers`.
- Unknown `/.well-known` documents answer 404 instead of 400.
- Request bodies are limited to 1 MiB (`max_content_length`).
- Content-Security-Policy: inline scripts use a per-request nonce instead of `'unsafe-inline'`; `style-src` is `'self' 'unsafe-inline'`.
- Revocation links pass `frontend_id`, so the backend lists only this frontend's credentials.
- The consent page shows the attributes named in `image_attributes` as images.
- Accessibility: labels tied to their controls, `alt` text on images, no `accesskey`.
- CSRF (S4502) and CORS (S5122) SonarCloud hotspots documented and marked `# NOSONAR`.
- `requests` 2.34.2, `werkzeug` 3.1.9, `Flask-Cors` 6.0.5.
- Removed unused requirements (`Flask-Session`, `flask_api`, `validators`, `jsonschema`, `config`), templates and imports.
- `pipeline.yml` runs on `main` and `branch-*` instead of `dev`, `preprod` and `main`.

### Fixed
- The PID login page polled and opened frontend URLs instead of the backend's `/pid_authorization` and `/getpidoid4vp`.
- The "back" links of the PID login and revocation QR pages pointed to frontend paths that do not exist.
- `Accept: application/jwt` without signed metadata returned 500 instead of 406.
- The authorization server metadata listed `public` instead of `none` in `token_endpoint_auth_methods_supported` (upstream #14).
- The 404 handler logged a stack trace.
- QR codes were too small for some phones to scan; they are scaled to 200-280 px.
- `install.md` and `licenses.md` listed gunicorn, which is not a dependency.
- `install.md`: wrong example and target configuration file names; the Docker steps linked a missing `.env.example`.
