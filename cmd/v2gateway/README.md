# V2 local gateway

The gateway exposes only fixed `POST` endpoints on `127.0.0.1:18742`. It uses the dashboard's ephemeral `X-App-Token` internally and never exposes that token, credentials, cookies, family identifiers or dashboard error bodies to V2. The one-shot family-add endpoint can receive the target Apple ID and password from V2 for a user-requested operation; it does not persist or return the password. The gateway does not support account creation, SMS or an unknown-outcome reset endpoint.

`POST /v1/accounts/list` accepts `{}` and returns only registered account IDs and normalized Apple IDs, for example `{"ok":true,"accounts":[{"account_id":"<id>","apple_id":"<apple-id>"}]}`. It reads the local registry only and does not contact Apple or the dashboard. Duplicate account IDs, duplicate Apple IDs, or an invalid registry fail the entire request; no partial account list is returned. The endpoint uses the same bearer, loopback, no-Origin, no-cookie and JSON request requirements as the other gateway routes.

Configuration:

- `V2GATEWAY_BEARER_TOKEN`: random secret of at least 32 bytes, supplied through the process environment. Do not put it on the command line or in a file.
- `V2GATEWAY_REGISTRY`: absolute path to the dashboard's generated `accounts.json` registry (`{"accounts":[{"id":"...","apple_id":"...","dir":"..."}]}`). This is not the launcher credentials file that contains passwords. On Windows, the path must resolve to D:.
- `V2GATEWAY_INTENT_DIR`: absolute D: directory for durable family mutation intents and outcomes.
- `V2GATEWAY_DASHBOARD_URL`: optional same-host dashboard URL; defaults to `http://127.0.0.1:18741`.
- `V2GATEWAY_LISTEN_ADDR`: optional listener; defaults to `127.0.0.1:18742`. Other bind addresses are rejected.

The caller must use one-time `operation_id` values for add/remove. An interrupted or failed mutation is permanently marked `outcome_unknown` for that organizer. V2 must not retry it. The gateway has no API that clears this block.

For organizer-only removal, `POST /v1/family/roster` reads the current organizer's family and returns redacted labels and opaque member references. `POST /v1/family/remove-by-ref` uses one of those references and an operation ID; it does not require the member to be registered or logged in. The dashboard rejects stale or ambiguous references, organizers, and child accounts before submission. An unconfirmed submission remains blocked across restarts. These endpoints have been tested with synthetic data; a real Apple removal has not been validated for this implementation.

For `POST /v1/family/add-with-credential`, the gateway must uniquely bind `target_apple_id` to `target_account_id`, verify the target worker's one-shot capability, and journal the operation before invoking the mutation. The target password belongs only in the authenticated request body and the short-lived worker/helper handoff, never in a URL, log, journal or response. Send it only on the user's explicit add action. Repeating an existing operation ID must return its recorded outcome without another mutation. This pathway requires both updated services and has only been exercised with synthetic data; it does not guarantee that Apple will accept an expired session or waive further verification.

For cross-machine access, forward the gateway's loopback port through SSH from the V2 host:

```text
ssh -N -L 127.0.0.1:18742:127.0.0.1:18742 <service-host>
```

The SSH tunnel provides the encrypted transport. V2 calls `http://127.0.0.1:18742` on its own host and supplies `Authorization: Bearer <secret>`. Do not expose the gateway listener on a LAN or public interface.

See [deployment notes](../../docs/v2-device-gateway.md) for account matching, current limits, and verification status.
