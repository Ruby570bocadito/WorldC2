# WorldC2 Console — E2E browser tests (Playwright)

Browser-level end-to-end tests for the operator console. They drive a
**real server build** through the real UI: login, dashboard, sessions
filters, vault create/search/export/delete (including the two-step
`ConfirmModal` flow), and logout.

> Complementary to `tests/e2e_test.py`, which exercises the
> agent↔server protocol from Python. This suite exercises what an
> operator actually clicks.

## Prerequisites

1. Build the server and the console from the repo root:

   ```bash
   make build           # or: cd src/go && go build -o dist/worldc2-server ./cmd/server
   cd web && npm ci && npm run build && cd ..
   ```

2. Start a server that serves the SPA (a throwaway config is fine —
   default credentials `admin`/`admin` on first run):

   ```bash
   cd /tmp/worldc2-e2e && cp /path/to/config.yaml . && worldc2-server -config config.yaml
   ```

3. Install the test dependencies (once per machine):

   ```bash
   cd tests/e2e
   npm install
   npx playwright install chromium
   ```

## Running

```bash
cd tests/e2e
npm test                                   # default http://127.0.0.1:19090, admin/admin

WORLDC2_BASE_URL=https://c2.lab:8443 \
WORLDC2_USER=alice WORLDC2_PASS='...' npm test
```

| Variable           | Default                  | Meaning                |
| ------------------ | ------------------------ | ---------------------- |
| `WORLDC2_BASE_URL` | `http://127.0.0.1:19090` | Console origin         |
| `WORLDC2_USER`     | `admin`                  | Operator username      |
| `WORLDC2_PASS`     | `admin`                  | Operator password      |

The Makefile target wires the usual flow:

```bash
make test-e2e    # builds the console, then runs the suite against BASE_URL
```

## What the suite asserts

- **Login** lands on the dashboard and stat cards render.
- **Sessions** view exposes its filters, including the round-16
  time-window select (`?days=`).
- **Vault** full cycle: create → debounced search (`?q=`) → CSV export
  emits a `worldc2-vault-YYYY-MM-DD.csv` download → delete guarded by
  `ConfirmModal`, with **Esc canceling safely** and a second confirm
  actually removing the row.
- **ConfirmModal contract**: focus starts on the safe control, Esc never
  confirms, and phrase-required variants stay disabled until the exact
  phrase is typed.
- **Logout** returns to the login page.

Failures retain a Playwright trace + screenshot under `test-results/`
(already `.gitignore`d) for post-mortem.
