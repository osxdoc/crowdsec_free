# Self-hosted CrowdSec: no console, no subscription

The Security Engine is open source and always was. What is not open is the
hosted console at `app.crowdsec.net` (web UI, fleet management, some blocklists)
and the Central API (CAPI) that it talks to. This fork adds two small services so
a deployment can be monitored, configured and kept up to date without an account:

| Component | Purpose |
| --------- | ------- |
| `cswebui` | Self-hosted web UI: dashboard, alerts, decisions, allowlists, config editor, engine reload |
| `csblocklistd` | Self-hosted CAPI-compatible server: engines register, push signals and pull a shared blocklist |
| `cscli capi register --url ...` | One added flag so engines can register against your own server |

Nothing here removes features from the engine; it replaces the parts that
required the paid console.

## Build

```sh
gmake build          # crowdsec + cscli (GNU make >= 4.1; `make` on macOS is too old)
gmake build-tools    # cswebui + csblocklistd
```

Binaries are written to `./cswebui` and `./csblocklistd`.

## Docker Compose (recommended for a separate host)

`deploy/docker/` contains a single-image stack with the engine, `cscli`, the web
UI and the blocklist server:

```sh
cd deploy/docker
cp .env.example .env      # set WEBUI_ADMIN_PASSWORD and BLOCKLIST_ADMIN_TOKEN
docker compose up -d --build
docker compose logs -f bootstrap    # credentials, hub and GeoIP download
```

Open `http://<host>:8081`. Two idempotent one-shot services provision the stack:
`bootstrap` (config, secrets, validated machines, hub/GeoIP) runs before
`csblocklistd`, and `register` subscribes the engine once the blocklist server is
healthy.

See [deploy/docker/README.md](../deploy/docker/README.md) for log sources,
ports, bouncers, backups and troubleshooting.

## Web UI

```sh
sudo install -m 0755 cswebui /usr/local/bin/
sudo install -m 0600 config/webui.yaml /etc/crowdsec/webui.yaml
cswebui -hash-password            # paste the hash into auth.users[].password_hash
sudo systemctl enable --now cswebui   # or use build/systemd/cswebui.service
```

Open `http://127.0.0.1:8081` (tunnel with SSH or put a TLS reverse proxy in
front; do not expose it directly).

The UI authenticates against local accounts (bcrypt, server-side session cookie,
CSRF token on every write). It logs in to the local API with the machine
credentials of `lapi.credentials_path`, which by default are the agent's own
credentials — nothing to register.

Pages:

- **Dashboard** — alerts, events and unique sources, timeline, top countries,
  scenarios, AS and sources, decision counts by origin, machines and bouncers,
  parser/bucket panels and the shared blocklist counters.
- **Alerts** — filter by scenario/IP, inspect events and decisions, delete.
- **Decisions** — everything the LAPI considers active, including entries pulled
  from the shared blocklist (`Origin: CAPI`). Manual bans and unbans.
- **Geo** — world map of the alert origins (bubbles sized by alert count),
  countries, networks (AS) and geo-enriched alerts.
- **Infrastructure** — machines and bouncers from the LAPI database (version,
  OS, scenarios, last heartbeat/pull), LAPI route usage and enabled features.
- **Metrics** — parser hits/errors, parse time, buckets, acquisition lines, LAPI
  and CAPI counters, per-parser and per-bucket tables.
- **Allowlists** — read-only view of centralized allowlists and their items.
- **Shared blocklist** — only with `blocklist.admin_url` configured: entries,
  connected engines, add/remove entries.
- **Configuration** — edit the whitelisted files, YAML is validated before
  writing, the previous version is kept as `<file>.bak`, then "Reload engine"
  applies the change.

### Reloading the engine

`engine.pid_file` (SIGHUP) or `engine.reload_command` (any command) is used to
apply changes:

```yaml
engine:
  reload_command: ["/bin/systemctl", "reload", "crowdsec"]
  # or, when cswebui runs as the crowdsec user:
  # reload_command: ["/usr/bin/pkill", "-HUP", "-x", "crowdsec"]
```

Without either, the UI saves the files but reports that no reload method is
configured.

### Which files are editable

Only names listed in `files` are readable/writable, and only below
`engine.config_dir`. Path traversal is rejected. Keep credential files
(`local_api_credentials.yaml`, `online_api_credentials.yaml`) out of that list,
and preferably edit `config.yaml` only if you know what a reload picks up.

## Shared blocklist server

```sh
sudo install -m 0755 csblocklistd /usr/local/bin/
sudo install -m 0600 config/blocklist.yaml /etc/crowdsec/blocklist.yaml
sudo mkdir -p /var/lib/crowdsec
csblocklistd -gen-admin-token        # put it in admin_token, also in webui.yaml
sudo systemctl enable --now csblocklistd
```

Then point each engine at it:

```sh
sudo cscli capi register --url http://blocklist.internal:8082/ \
    -f /etc/crowdsec/online_api_credentials.yaml
sudo systemctl reload crowdsec
```

`--url` defaults to `https://api.crowdsec.net/`, so existing behaviour is
unchanged. The URL, login and password end up in
`online_api_credentials.yaml`; the engine uses them for the CAPI push/pull, so
no other engine configuration changes.

The server speaks the CAPI v3 endpoints the engine uses (`/v3/watchers`,
`/v3/watchers/login`, `/v3/signals`, `/v3/decisions/stream`, plus the
v1 aliases), stores everything in SQLite and supports delta pulls per machine.

### What is shared

Engines push signals every ~10 seconds with the alerts selected by
`console.yaml` (`share_manual_decisions`, `share_custom`, `share_tainted`).
The server keeps only decisions whose origin is in `push.accept_origins`
(default: `cscli`, i.e. manual bans) and only for `ip`/`range` scopes, then
serves the aggregated list to every registered engine as
`crowdsec/community-blocklist`.

- Enable sharing of manual bans on the engine in `console.yaml`:
  `share_manual_decisions: true`
- Add `crowdsec` to `accept_origins` to share scenario-generated decisions too
  (usually noisy; their scenarios are instance-local).
- Simulated decisions and non-`ban` types are never shared.
- Durations are normalised to Go syntax (`1d` → `24h0m0s`) because the engine
  parses them with `time.ParseDuration`.

Admins can also add entries directly (`POST /admin/v1/decisions`, or the web UI
when `blocklist.admin_url` is set). These are served to all engines until they
expire or are removed; removing one produces a deletion in the next delta pull.

### API tokens

- `admin_token` protects `/admin/v1` (stats, decisions, machines). When empty,
  only loopback clients are accepted.
- `registration_token` can gate `POST /v3/watchers`, but `cscli capi register`
  cannot send it. Leave it empty and restrict the listening interface instead.

## Extra data sources

Two optional read-only sources feed the richer pages:

```yaml
data:
  # SQLite database of the LAPI: machines, bouncers, geo/AS aggregates.
  # Defaults to db_config.db_path from <config_dir>/config.yaml.
  db_path: /var/lib/crowdsec/data/crowdsec.db
  # Prometheus endpoint of the engine.
  metrics_url: http://127.0.0.1:6060/metrics
```

- The database is opened read-only (`mode=ro`). Only SQLite is supported; with
  MySQL/PostgreSQL the machine/bouncer pages stay empty and the dashboard falls
  back to what the HTTP API can derive.
- Metrics require `prometheus.enabled: true` in the engine config. Set
  `prometheus.level: full` for parser/bucket/acquisition metrics. In Compose the
  endpoint listens on `0.0.0.0:6060` inside the stack and is not published.

Country, AS and coordinates come from the GeoIP enrichment, which needs
`GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` in the data directory
(`cscli hub update --with-content` downloads them). Without them the map shows
`No GeoIP data yet` and the country/AS columns stay empty.

The map itself is a 25 KB simplified Natural Earth 110m land outline (public
domain) embedded in the UI — no external tiles, no network calls.

## Architecture notes

```
                     ┌──────────────┐
   logs ───────────► │  crowdsec    │ ◄── config files ── cswebui (HTTP UI)
                     │  engine+LAPI │
                     └──────┬───────┘
                            │ CAPI v3 (signals / decisions stream)
                            ▼
                     ┌────────────────┐
                     │  csblocklistd  │ ── SQLite
                     └────────────────┘
```

`cswebui` is stateless: it holds a machine JWT to the local API and a list of
allowed config files. Sessions live in the process, so a restart logs users out.

## Limitations

- Console features that are not just a UI (fleet-wide views across many
  engines, managed blocklist subscriptions, PAPI) are not reimplemented. The
  blocklist server is a flat shared list, not a multi-tenant service.
- `console enroll` is not supported; the server answers 501 with a hint.
- If `online_api_credentials.yaml` points at a server that is down or no longer
  knows the machine, the engine fails at startup when it validates the CAPI
  credentials. Keep the blocklist server reachable, or clear the credentials
  file to run without CAPI.
- The web UI shows decisions derived from alerts (the local API only exposes the
  raw decision list to bouncer keys), so the numbers match what `cscli decisions
  list --all` reports.
- Engines pull the stream every 2 hours (upstream default). Changes reach other
  engines with that delay; restarting an engine triggers an immediate pull.
- Machine/bouncer statistics need a readable SQLite database on the same host
  (the Compose stack shares the data volume). Host-based MySQL/PostgreSQL setups
  only get the API and metrics views.

## Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| `no LAPI credentials` | Start the engine once, then `cscli lapi register -f /etc/crowdsec/local_api_credentials.yaml` (or `cscli machines add --auto`) |
| `password_hash is not a bcrypt hash` | Run `cswebui -hash-password` and paste the output |
| `invalid CSRF token` | Reload the page after restarting `cswebui` (sessions are in memory) |
| `engine reloaded` but nothing changed | Check the reload command / pid file, and `journalctl -u crowdsec` |
| Engines pull nothing | `scenario list is empty, will not pull yet` in the engine log: install at least one scenario, then reload |
| `401` on `/v3/watchers/login` | The machine was removed from the blocklist DB; register again with `--url` |
| Blocklist pull works, decisions stay empty | They are stored with origin `CAPI`; use `cscli decisions list --all` or the Decisions page |

## Verified end to end

The setup in this repository was tested with a real engine on a scratch config:
engine registered against `csblocklistd` via `cscli capi register --url`, pulled
a seeded range into its decision table (origin `CAPI`), pushed a manual ban that
appeared in the server admin API, and `cswebui` showed both, created and deleted
a decision, edited `console.yaml` (backup created) and reloaded the engine.
`go test ./pkg/blocklistserver/ ./pkg/webui/` covers the API, auth, stream
deltas, duration normalisation, config editing, the Prometheus parser and the
database aggregates.

The Compose configuration was exercised with the same files path-rewritten on a
host: bootstrap (machines, CAPI registration, hub install), engine with parsers,
GeoIP enrichment (country/AS), metrics scraping and all UI pages. The Docker
image itself was not built in the development environment (no Docker daemon);
the static builds it runs (`CGO_ENABLED=0`, tag `sqlite_modernc`) were verified.
