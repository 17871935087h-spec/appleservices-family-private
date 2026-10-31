# V2 local gateway

The gateway exposes only six `POST` endpoints on `127.0.0.1:18742`. It uses the dashboard's ephemeral `X-App-Token` internally and never exposes that token, Apple IDs, credentials, cookies, family identifiers or dashboard error bodies to V2. The gateway does not support account creation, password entry, SMS or an unknown-outcome reset endpoint.

Configuration:

- `V2GATEWAY_BEARER_TOKEN`: random secret of at least 32 bytes, supplied through the process environment. Do not put it on the command line or in a file.
- `V2GATEWAY_REGISTRY`: absolute path to the dashboard's generated `accounts.json` registry (`{"accounts":[{"id":"...","apple_id":"...","dir":"..."}]}`). This is not the launcher credentials file that contains passwords. On Windows, the path must resolve to D:.
- `V2GATEWAY_INTENT_DIR`: absolute D: directory for durable family mutation intents and outcomes.
- `V2GATEWAY_DASHBOARD_URL`: optional same-host dashboard URL; defaults to `http://127.0.0.1:18741`.
- `V2GATEWAY_LISTEN_ADDR`: optional listener; defaults to `127.0.0.1:18742`. Other bind addresses are rejected.

The caller must use one-time `operation_id` values for add/remove. An interrupted or failed mutation is permanently marked `outcome_unknown` for that organizer. V2 must not retry it. The gateway has no API that clears this block.

For cross-machine access, forward the gateway's loopback port through SSH from the V2 host:

```text
ssh -N -L 127.0.0.1:18742:127.0.0.1:18742 <service-host>
```

The SSH tunnel provides the encrypted transport. V2 calls `http://127.0.0.1:18742` on its own host and supplies `Authorization: Bearer <secret>`. Do not expose the gateway listener on a LAN or public interface.

See [deployment notes](../../docs/v2-device-gateway.md) for account matching, current limits, and verification status.
