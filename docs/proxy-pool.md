# Account proxy pool

`APPLESERVICES_PROXY_POOL` selects a private JSON file on the Windows server.
Each account directory is assigned one node persistently. New assignments are
serialized across processes, grouped by the **observed exit IP**, and limited
by `max_accounts_per_exit` (default: 1). Restarting a worker keeps its assignment.
Unreachable proxies do not trigger direct access or automatic node switching.

Keep this file outside the checkout, for example
`D:\DeviceData\private\proxy-pool\pool.json`. Restrict its directory ACL to the
service identity and administrators: proxy URLs may contain credentials.
Never commit a real configuration.

```json
{
  "version": 1,
  "max_accounts_per_exit": 1,
  "nodes": [
    {
      "id": "exit-a",
      "url": "http://proxy-a.example:8080",
      "exit_ip": "192.0.2.10",
      "enabled": true
    },
    {
      "id": "exit-b",
      "url": "socks5h://proxy-b.example:1080",
      "exit_ip": "192.0.2.11",
      "enabled": true
    }
  ],
  "assignments": {}
}
```

HTTP, HTTPS, SOCKS5, and SOCKS5H URLs are supported. Measure each node's real
exit from the Windows server before enabling it. Several gateway usernames or
ports can share one exit. A rotating or short-lived proxy cannot guarantee a
stable account exit; use dedicated stable nodes and verify their lifetime.
Importing a node does not probe it or reserve it in another application's pool.

## Commands

```powershell
$env:APPLESERVICES_PROXY_POOL='D:\DeviceData\private\proxy-pool\pool.json'
& 'D:\DeviceData\releases\account-proxy-pool\proxy-pool.exe' inspect
& 'D:\DeviceData\releases\account-proxy-pool\proxy-pool.exe' assign -account-dir 'D:\DeviceData\state\accounts\01-account'
```

Inspect and assign print account labels, node IDs and exit IPs, without URLs or
proxy credentials.

Workers publish only `proxy_node_id` and `proxy_exit_ip` in `runtime.json`.
If a running worker predates the pool or reports another assignment, the
dashboard asks for an account-specific stop and saved-session recovery rather
than reporting that its new proxy has already been applied.

Configure the pool variable in both the dashboard runner and any worker
recovery runner **after** their existing environment cleanup. Do not configure
it globally for unrelated programs. Existing workers retain their previous
environment until individually stopped and restored from saved sessions.

Before activation: validate the private file, verify all required exit routes,
back up the runners, and retain the previous binaries. Change workers one at a
time using the dashboard's account-specific stop/resume operations. Stop an
account's migration if Apple requires fresh authentication or verification.
Do not overwrite device/session files or bulk reauthenticate accounts as part
of installing the pool. A disabled, missing, corrupt or full configured pool
blocks new network clients; it does not select the ordinary server exit.

## Coverage and limits

The route is applied to trusted-device GSA login/session recovery, refresh and
APS courier transport, account-bound iCloud/HME and management clients, family
helpers, quota queries and primary-mail helpers. Shared dashboard clients bind
the account route directly and never temporarily change the dashboard's
process environment. Local control endpoints continue to use loopback.

The separate primary-mail Web login binary is built from the V2 repository;
deploy its account-proxy-capable version and `account-http.exe` alongside the
Python helper. Python primary-mail requests use the latter over private pipes,
so the isolated Python runtime needs no proxy dependency packages. The pool does
not change the independent Linux V2 or registrar service's network settings.

The optional legacy Python Store mode is blocked when an account route is
configured; the Go Store transport supports account routes. No Store login or
purchase is part of proxy installation or its offline tests.

The pinned native APS bootstrap has no verified proxy interface. Existing
account-private push identities continue to work through the Go courier.
With a pool configured, creating a missing APS identity is blocked before the
native bootstrap starts, avoiding an unassigned direct connection. That
bootstrap must gain proxy support before fully new device provisioning can
run under this pool.

To retire a node, first stop its workers; edit assignments only through an
explicit migration. Changing a node URL or its upstream exit while its workers
are running does not change already-created transports. Account deletion does
not silently reuse its assignment; review retired mappings before reclaiming
capacity.
