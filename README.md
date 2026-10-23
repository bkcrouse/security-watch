# Security Watch

A static dashboard of vulnerabilities worth acting on, rebuilt every 15 minutes by GitHub Actions and served from GitHub Pages. There's no server and no database.

It shows:

- everything CISA added to its **Known Exploited Vulnerabilities** catalog in the last 30 days
- CVEs rated **critical** (CVSS 9+) in **NVD** or the **GitHub Advisory Database** in the last 7 days
- **malicious npm/PyPI packages** with at least 50,000 downloads a month

Each entry is scored on exploitation in the wild, ransomware use, FIRST **EPSS**, CVSS, how widely used and internet-facing the product is, your **watchlist**, CISA deadlines and age. It is then sorted into `act`, `watch` or `fyi`, with a `why` list explaining the ranking.

## Layout

| Path | What it is |
|---|---|
| `scripts/build.py` | Fetches the feeds, merges, scores, and writes `data.json` + `feed.xml`. Uses only the Python standard library. |
| `web/` | Static front end (vanilla JS, no build step). Copied into the output directory. |
| `watchlist.json` | Products you run. Matches are boosted and flagged. Plain strings or `{"vendor","product"}`. |
| `overrides.json` | Hand curation: `patch` existing records (title, note, pinned), add `items` the feeds miss (e.g. supply-chain incidents with no CVE), or `suppress` IDs. |
| `tests/fixtures/` | Sample upstream data for offline builds. CI runs a smoke build against it first. |
| `.github/workflows/build.yml` | Runs every 15 minutes, on push, or manually, then deploys to Pages. |

## Run locally

```bash
python scripts/build.py --out site                                   # live feeds
SW_NOW=2026-10-23T23:00:00Z python scripts/build.py --fixtures tests/fixtures --out site   # offline
python -m http.server -d site 8000
```

Set `GITHUB_TOKEN` for higher GitHub API limits and `NVD_API_KEY` for faster NVD lookups (both optional locally).

## Setup notes

- **Pages source** must be set to **GitHub Actions** (Settings → Pages).
- Optional: add an `NVD_API_KEY` repository secret ([request one free](https://nvd.nist.gov/developers/request-an-api-key)). Without it NVD allows 5 requests per 30 seconds, which slows the first build. Later runs are faster because NVD lookups are cached for 6 hours.
- GitHub runs schedules best-effort, so builds can drift a few minutes. Scheduled workflows on public repos are paused after 60 days without a commit; any push restarts them.
