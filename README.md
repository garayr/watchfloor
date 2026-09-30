# Watchfloor

A cyber security dashboard with five tabs: alerts, a global attack map, news, incidents (ransomware claims and confirmed breaches) and threats (malware, scanning and campaign reports).
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

## Real attack data on the map

With a Cloudflare API token saved as the repository secret `CLOUDFLARE_API_TOKEN` (permission: Account → Radar → Read), the fetcher pulls the busiest attack routes from Cloudflare Radar about once an hour. It pulls both web application attacks (layer 7) and network DDoS attacks (layer 3) for the last 24 hours, and saves them to `docs/data/attacks.json`.

The map then replays those routes, drawing busier routes more often. Each arc stands for a share of attack traffic, not a single attack. Without the token, or if Radar is unavailable, the map falls back to simulated traffic and says so.

If the Actions log says a country has "no map location", add its two-letter code and rough coordinates to `COUNTRY_LOC` in `scripts/fetch_feeds.py`.

## Phone alerts for new Critical items

1. Install the **ntfy** app (free, iPhone and Android) and allow notifications.
2. In the app, tap **+** and subscribe to a topic name only you know, like `watchfloor-` followed by a string of random letters and numbers. Anyone who knows the name can read the alerts, so treat it like a password.
3. In your repo, go to Settings → Secrets and variables → Actions and add a secret called `NTFY_TOPIC` containing that exact name.

The first run after that quietly records the Critical alerts already on the list. After that you get one notification per new Critical alert, and tapping it opens the CVE record. More than five at once become a single summary message.

## Using the dashboard

- **Search** boxes on the alerts and news tabs match titles, vendors, descriptions and CVE numbers.
- **In the news:** when a news story names an alert's CVE, or names both its vendor and product, the alert gets an "In the news" label with links. The story shows which alerts it relates to, and clicking one jumps to that alert. "Only in the news" filters to those alerts.
- **Mark as patched / Not relevant to me** hides an alert and takes it out of the counts. This is saved in your browser only, so each device keeps its own list. Choose "Handled" to see them again, or "Undo" to restore one.
- **Map:** click a country dot, or use "Focus on a country", to see only that country's attack routes. The 7-day chart shows hourly attack volume for each type, and whether the last 24 hours were busier than the 6 days before.

## Weekly digest

If phone alerts are set up, you also get a summary every Monday at 7am UTC (8am UK summer time, 7am in winter). It covers the week's Critical and High counts, the Critical alerts, the alerts most mentioned in the news, and the latest headlines. Tapping it opens your dashboard.
To change the day or time, add `DIGEST_WEEKDAY` (0 = Monday … 6 = Sunday) or `DIGEST_HOUR_UTC` to the `env:` section of the "Fetch feeds" step in the workflow.

## Incidents and Threats tabs

**Incidents** shows ransomware claims from the last 7 days (Ransomware.live) and breaches added to Have I Been Pwned in the last 60 days. Neither needs a key. Ransomware claims are the gangs' own posts and aren't independently confirmed; the page says so. Only organisation names, dates, sectors and countries are kept, never links to leak sites. The countries with the most claims also appear as markers on the map.

**Threats** shows the SANS Internet Storm Center threat level (also in the page header), the most scanned ports, the SANS diary, the most active malware from abuse.ch ThreatFox, malicious links from abuse.ch URLhaus, and campaign reports from AlienVault OTX.

Two of these need free keys, saved as repository secrets like the others:

| Secret | Where to get it |
|---|---|
| `ABUSECH_AUTH_KEY` | Sign in at https://auth.abuse.ch (you can use your GitHub account), then copy your Auth-Key from your profile. One key covers ThreatFox and URLhaus. |
| `OTX_API_KEY` | Sign up at https://otx.alienvault.com, then open Settings and copy your OTX Key. New accounts follow AlienVault's own research team, which is where the campaign reports come from. |

Without a key, that part of the Threats tab simply says it needs one; everything else keeps working.

These sources refresh hourly rather than every 15 minutes. SANS asks for no more than hourly downloads, and Ransomware.live is run by a volunteer, so it's polite to go easy on it. The hourly timing is tracked in `cache/schedule.json`.

Please keep the credits on the Threats tab. SANS and Have I Been Pwned require attribution, and it's good manners for the others.

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
- Attack map data comes from Cloudflare Radar, and the map credits it. Check Radar's licence terms before using the data anywhere else.
