# Configuration

For configuring your locally installed version of the EUDIW Issuer Front-end, you need to change the following configurations.

## 1. Service Configuration

Base configuration example for the EUDIW Issuer Front-end is located in [frontend_config_example.yaml](../frontend_config_example.yaml).

Parameters that should be changed:

- `service_url` (Base url of the service)
- `frontend_id` (The front-end id registered in the backend service)
- `backend_url` (Public base url of the back-end service; pages only post to, and navigate to, URLs on this origin)
- `backend_origins` (Optional list of other public origins of the back-end, if browsers reach it under more than one)
- `backend_api_key` (API key sent to the backend in the `X-Api-Key` header; must match the backend's `backend_api_key`; secret)
- `log_dir` (Log file; its directory is created at start-up)

Optional parameters (defaults in brackets):

- `log_level` [`INFO`] (`DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`)
- `payload_key` [unset] (Shared secret, at least 32 characters, the same value as `frontend.frontends_config.<frontend_id>.payload_key` in the backend. When set, the `/display_*` pages only accept payloads the backend signed (`payload_jwt`, HS256, `aud` = `frontend_id`); when unset they accept unauthenticated payloads and a warning is logged at start-up; secret)
- `max_content_length` [`1048576`] (Largest request body in bytes; larger requests get 413)

`backend_url` must be https; plain http is only accepted for `localhost`, `127.0.0.1` and `::1`, because the API key is sent to it.

Every key is described in [frontend_config_example.yaml](../frontend_config_example.yaml).

The front-end's metadata (`/.well-known/openid-credential-issuer` and `/.well-known/jwt-vc-issuer`) is loaded from the backend at start-up (`GET /metadata/<frontend_id>` and `GET /metadata/<frontend_id>/signed`). The credentials it advertises (`credentials_supported`) are therefore configured in the backend, under `frontend.frontends_config.<frontend_id>`. Its `authorization_servers` names the front-end's own issuer at the authorization server, `<authorization_server.base_url>/<frontend_id>`: wallets push authorization requests to, and read the metadata of, that issuer, not the front-end.
