# Watchfloor

A cyber security dashboard with three tabs: live alerts, a global attack map and a news roundup.
A scheduled GitHub Action fetches the feeds every 15 minutes and saves them as JSON files.
GitHub Pages serves the page, and the page reads those files.

No server and no cost. Everything runs on a free GitHub account.

## What's in here

| Path | What it does |
|---|---|
| `docs/index.html` | The dashboard page |
| `docs/data/alerts.json`, `news.json`, `meta.json` | Written by the fetcher. Start empty. |
| `docs/data/incidents.json` | Optional pins for the map. You edit this by hand. |
| `scripts/fetch_feeds.py` | The fetcher. Python standard library only. |
| `.github/workflows/update-feeds.yml` | Runs the fetcher every 15 minutes |
| `cache/cvss.json` | Remembers CVSS scores so they aren't looked up again |

## Set it up

1. **Create a repository.** On GitHub, click New repository and name it `watchfloor`. Public is simplest, because GitHub Pages on private repos needs a paid plan.
2. **Upload the files.** Click "uploading an existing file" and drag in everything from this folder, keeping the folder structure. The `.github` folder is hidden on Mac and Linux, so check it's included. On a Mac, press Cmd+Shift+. in Finder to show it.
3. **Let the workflow write to the repo.** Go to Settings, then Actions, then General. Under Workflow permissions choose "Read and write permissions" and save.
4. **Turn on Pages.** Go to Settings, then Pages. Under Source choose "Deploy from a branch", pick `main` and the `/docs` folder, and save.
5. **Run the first update.** Go to the Actions tab, open "Update feeds", and click Run workflow. It takes about two minutes, mostly waiting politely between NVD lookups.
6. **Open the page.** Its address is shown on the Pages settings screen, usually `https://YOUR-USERNAME.github.io/watchfloor/`. GitHub can take a minute or two to publish after each update.

After that it runs by itself every 15 minutes.

## Optional: faster CVSS scores

Without a key, the fetcher looks up 12 new CVSS scores per run, which is NIST's limit for anonymous use. The rest fill in over the next few runs. A free key from https://nvd.nist.gov/developers/request-an-api-key raises this to 40 per run.
Add it under Settings, then Secrets and variables, then Actions, as a secret named `NVD_API_KEY`.

## How severity is decided

Everything on CISA's Known Exploited Vulnerabilities list is being attacked, so it starts at **High**.
It becomes **Critical** if any of these is true:

- CISA says ransomware gangs use it
- its CVSS score is 9.0 or more
- its EPSS score is 50% or more, meaning exploitation is very likely to spread

NCSC items titled "Alert" and CISA joint advisories (AA numbers) are High. ICS advisories and other NCSC threat items are Medium. Other CISA items are Info.
You can change these rules in `score_kev()` and `advisory_severity()` in `scripts/fetch_feeds.py`.

## Changing the sources

Feed URLs are listed near the top of `scripts/fetch_feeds.py` in `ADVISORY_FEEDS` and `NEWS_FEEDS`. Add or remove entries there. Any RSS or Atom feed works.

## Preview on your own computer

Opening `docs/index.html` directly won't load the data, because browsers block that. Instead run:

```
python scripts/fetch_feeds.py
cd docs
python -m http.server 8000
```

Then open http://localhost:8000.

## When something breaks

- **A source shows as failed on the page.** That feed didn't respond or changed format. The others keep working. Open the latest run in the Actions tab and look at the "Fetch feeds" step for the error.
- **The whole run goes red.** Every source failed at once. This is usually a network blip, so wait for the next run.
- **Updates stop.** GitHub pauses scheduled workflows after 60 days with no commits to the repo. The fetcher commits whenever there's new data, so this is unlikely, but you can re-enable it in the Actions tab.
- **Runs are late.** GitHub runs scheduled jobs when it has capacity, so "every 15 minutes" can sometimes be 20 or 30.

## Notes

- News items show the headline, a short snippet from the publisher's feed and a link. Full articles are not copied.
- The map's attack arcs are still simulated, and the page says so. Real attack data from Cloudflare Radar is the next step.
