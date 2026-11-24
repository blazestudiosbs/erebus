# Erebus lab range

Local, deliberately-simple targets for the integration tests and hands-on
practice. **Authorized, local use only** — every port binds to `127.0.0.1`;
never expose these off your machine.

## Run

```bash
cd labrange
docker compose up -d        # web on 127.0.0.1:8081, DVWA on :8082
```

Then run the integration suite (opt-in):

```bash
EREBUS_LABRANGE=1 pytest tests/integration -v
```

Tear down:

```bash
cd labrange && docker compose down
```

## Targets
- **web** (`:8081`) — nginx serving `web/` (title "Erebus Lab Target", a
  `/robots.txt`, and an `/admin/` path). Deterministic; the tests assert on it.
- **dvwa** (`:8082`) — Damn Vulnerable Web App, for manual practice.

Override the web target with `EREBUS_LAB_HTTP=host:port` (default `127.0.0.1:8081`).
