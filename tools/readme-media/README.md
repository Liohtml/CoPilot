# README media

Regenerates the screenshots in `docs/assets/readme/screens/`, the product tour
(`docs/assets/readme/tour.gif`, `tour.mp4`) and three short clips (`gif-triage.gif`,
`gif-soc.gif`, `gif-portal.gif`) from a running CoPilot with fictional demo data.

| File | What it does |
|---|---|
| `seed_demo.py` | Seeds (or cleans) the demo data: four customers, a SOC team, ~300 alerts over 60 days, cases with playbook tasks and timelines, SLA history, AI Analyst reports, the Customer Portal switches. Prints the logins and the featured ids as JSON. |
| `capture.mjs` | Playwright: logs in through the UI and takes the raw captures (1440×900 at 2×, dark and light), or records the tour (`--tour`) and the clips (`--record gif-soc,gif-portal,gif-triage`). |
| `frame.py` | Pillow + ffmpeg: puts each capture in a browser window with a drop shadow (1600 px PNG under 500 KB), and turns a recording into its GIF (and the tour's MP4). |

## Steps

Needs a MySQL 8 server, the backend's Python virtualenv, Rust, Node ≥ 22 with pnpm, ffmpeg
and Pillow. Ports below are examples.

```bash
# 1. A database at the current schema
mysql -e "CREATE DATABASE copilot_readme"
export MYSQL_URL=127.0.0.1:3306 MYSQL_USER=copilot MYSQL_PASSWORD=… MYSQL_DATABASE=copilot_readme
export JWT_SECRET=$(openssl rand -hex 32)
cargo build -p copilot && ./target/debug/copilot migrate

# 2. Demo data (refuses any database whose name does not end in _readme)
cd backend
export README_DEMO_DB_URL=mysql+aiomysql://copilot:…@127.0.0.1:3306/copilot_readme
python ../tools/readme-media/seed_demo.py seed > /tmp/seed.json     # cleanup: … cleanup
cd ..

# 3. The backend and both frontends
COPILOT_PORT=7100 COPILOT_STARTUP_TASKS=false COPILOT_CATALOG_REFRESH=false \
  COPILOT_SIDEBAR_REFRESH=false ./target/debug/copilot serve &
(cd frontend && VITE_API_URL=http://127.0.0.1:7100 pnpm exec vite --port 7101 &)
(cd customer-portal && VITE_API_URL=http://127.0.0.1:7100 pnpm exec vite --port 7102 &)

# 4. Captures, then the framed images
cd tools/readme-media && npm install
SEED_JSON=/tmp/seed.json OUT=/tmp/readme-raw node capture.mjs          # ONLY=alerts,soc-sla to redo some
python frame.py stills /tmp/readme-raw ../../docs/assets/readme/screens

# 5. The tour and the clips (gif-triage edits the alert it plays with: record it last)
SEED_JSON=/tmp/seed.json OUT=/tmp/readme-raw node capture.mjs --record all
for r in tour gif-soc gif-portal gif-triage; do python frame.py tour /tmp/readme-raw/$r ../../docs/assets/readme; done
```

Re-seed right before capturing: every timestamp is relative to the moment of seeding, so the
dashboards show "today" and the SLA clocks that are about to run out.

## Notes

- Everything in the data is fictional: the customers and people, documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.example` domains.
- Pages that need Wazuh, Graylog, Velociraptor, Grafana or MinIO are left out: the demo has
  none of them. For the same reason the captures hide the sidebar's *Health* block, which
  would only report those missing tools, along with toasts, Vite's DevTools button and the
  chat launcher.
- Recordings cut out page-load time and play back faster than recorded (`--speed`: 1.1× for
  the tour, 1.4× for a clip). A GIF is 1200 px, 12 fps, 128 colours, and drops to a lower
  frame rate if it would exceed `--gif-budget` (5 MB for the tour, 3 MB for a clip).
- `CHROMIUM=/path/to/chrome` runs `capture.mjs` on a browser Playwright did not download.
