#!/usr/bin/env python3
"""
Watchfloor feed fetcher.

Pulls CISA's Known Exploited Vulnerabilities list, government advisory feeds
and security news RSS feeds, then writes three JSON files the page reads:

  docs/data/alerts.json   actively exploited flaws and advisories
  docs/data/news.json     the week's news, grouped by theme
  docs/data/meta.json     when it ran and which sources worked

Standard library only, so it runs on a plain GitHub Actions runner.
Every source is optional: if one fails, the others still update.
"""

import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

# ---------------------------------------------------------------- settings

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "data"
CACHE_FILE = ROOT / "cache" / "cvss.json"

USER_AGENT = "Watchfloor/1.0 (cyber alerts dashboard; GitHub Actions)"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_DAYS = 30                      # how far back to show KEV additions

ADVISORY_FEEDS = [
    {"name": "NCSC", "src": "NCSC", "url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"},
    {"name": "CISA advisories", "src": "CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
]
ADVISORY_DAYS = 30

NEWS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
]
NEWS_DAYS = 7
NEWS_MAX = 40
SNIPPET_CHARS = 220                # keep feed snippets short; link out for the rest

EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_MAX_LOOKUPS = int(os.environ.get("NVD_MAX_LOOKUPS", "40" if NVD_API_KEY else "12"))
NVD_PAUSE = 0.8 if NVD_API_KEY else 6.5   # NVD allows 5 requests / 30 s without a key

MAX_ALERTS = 120

NOW = datetime.now(timezone.utc)
status = []   # per-source results for meta.json


# ---------------------------------------------------------------- helpers

def log(msg):
    print(msg, flush=True)


def fetch(url, headers=None, timeout=30, tries=3):
    """GET a URL and return bytes. Retries on network errors and 5xx."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    hdrs.update(headers or {})
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code < 500 and e.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{url}: {last}")


def record(name, ok, count=0, error=None):
    status.append({"name": name, "ok": ok, "count": count, "error": error})
    log(f"{'OK  ' if ok else 'FAIL'} {name}: {count if ok else error}")


def clean_text(s, limit=None):
    """Strip HTML, unescape entities, collapse whitespace, trim at a word."""
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"<[^>]+>", " ", s)   # some feeds double-encode their HTML
    s = re.sub(r"\s+", " ", s).strip()
    if limit and len(s) > limit:
        s = s[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"
    return s


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        d = None
    if d is None:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def local(tag):
    """Tag name without its XML namespace."""
    return tag.rsplit("}", 1)[-1]


def child_text(el, *names):
    for c in el:
        if local(c.tag) in names and (c.text or "").strip():
            return c.text
    return ""


def parse_feed(data):
    """Parse RSS 2.0 or Atom into a list of {title, link, date, summary}."""
    root = ET.fromstring(data)
    items = []
    for el in root.iter():
        kind = local(el.tag)
        if kind not in ("item", "entry"):
            continue
        title = clean_text(child_text(el, "title"))
        link = child_text(el, "link").strip()
        if not link:  # Atom puts the URL in an attribute
            for c in el:
                if local(c.tag) == "link" and c.get("href") and c.get("rel", "alternate") == "alternate":
                    link = c.get("href")
                    break
        date = parse_date(child_text(el, "pubDate", "published", "updated", "date"))
        summary = child_text(el, "description", "summary", "content")
        if title and link:
            items.append({"title": title, "link": link, "date": date, "summary": summary})
    return items


def iso_day(d):
    return d.strftime("%Y-%m-%d") if d else None


# ---------------------------------------------------------------- KEV + enrichment

def load_kev():
    try:
        data = json.loads(fetch(KEV_URL))
        vulns = data.get("vulnerabilities", [])
    except Exception as e:  # noqa: BLE001
        record("CISA KEV", False, error=str(e)[:200])
        return []
    cutoff = (NOW - timedelta(days=KEV_DAYS)).date()
    alerts = []
    for v in vulns:
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").date()
        except (KeyError, ValueError):
            continue
        if added < cutoff:
            continue
        cve = v.get("cveID", "")
        alerts.append({
            "id": cve,
            "date": v["dateAdded"],
            "src": "CISA",
            "vendor": " ".join(x for x in [v.get("vendorProject", ""), v.get("product", "")] if x).strip(),
            "title": v.get("vulnerabilityName") or cve,
            "detail": clean_text(v.get("shortDescription", ""), 400),
            "todo": clean_text(v.get("requiredAction", ""), 300),
            "due": v.get("dueDate"),
            "ransomware": (v.get("knownRansomwareCampaignUse", "").lower() == "known"),
            "cves": [cve] if cve else [],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "kev": True,
        })
    record("CISA KEV", True, len(alerts))
    return alerts


def add_epss(alerts):
    cves = [a["id"] for a in alerts if a.get("kev")]
    if not cves:
        return
    scores = {}
    try:
        for i in range(0, len(cves), 50):
            q = urllib.parse.urlencode({"cve": ",".join(cves[i:i + 50])})
            data = json.loads(fetch(f"{EPSS_URL}?{q}"))
            for row in data.get("data", []):
                scores[row["cve"]] = float(row.get("epss", 0))
        record("FIRST EPSS", True, len(scores))
    except Exception as e:  # noqa: BLE001
        record("FIRST EPSS", False, error=str(e)[:200])
    for a in alerts:
        if a["id"] in scores:
            a["epss"] = round(scores[a["id"]], 4)


def add_cvss(alerts):
    cache = {}
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text())
        except json.JSONDecodeError:
            cache = {}
    todo = [a["id"] for a in alerts if a.get("kev") and a["id"] not in cache]
    looked, failed = 0, 0
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for cve in todo[:NVD_MAX_LOOKUPS]:
        try:
            data = json.loads(fetch(f"{NVD_URL}?cveId={cve}", headers=headers, tries=2))
            score = None
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(key):
                        score = metrics[key][0].get("cvssData", {}).get("baseScore")
                        break
            # Cache "not scored yet" as None only for a day, so we retry later.
            cache[cve] = {"score": score, "checked": NOW.strftime("%Y-%m-%d")}
            looked += 1
        except Exception as e:  # noqa: BLE001
            failed += 1
            log(f"  NVD lookup failed for {cve}: {e}")
        time.sleep(NVD_PAUSE)
    # expire unscored entries older than a day so they get another try
    today = NOW.strftime("%Y-%m-%d")
    cache = {k: v for k, v in cache.items() if v.get("score") is not None or v.get("checked") == today}
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=1, sort_keys=True))
    record("NVD CVSS", failed == 0 or looked > 0, looked,
           None if failed == 0 else f"{failed} lookups failed")
    for a in alerts:
        s = cache.get(a["id"], {}).get("score")
        if s is not None:
            a["cvss"] = s


def score_kev(a):
    """Everything in KEV is being exploited, so it starts at High.
    Critical if ransomware gangs use it, it's rated 9+, or EPSS says
    exploitation is very likely to spread."""
    if a.get("ransomware") or (a.get("cvss") or 0) >= 9 or (a.get("epss") or 0) >= 0.5:
        return "critical"
    return "high"


# ---------------------------------------------------------------- advisories

ADVISORY_KEEP = re.compile(r"\b(alert|advis|vulnerab|exploit|warn|threat|malware|ransomware|patch|attack|compromis|mitigat)", re.I)


def advisory_severity(src, title):
    t = title.lower()
    if src == "NCSC":
        return "high" if t.startswith("alert") else "medium"
    if re.search(r"\baa\d{2}-\d{3}", t) or "joint" in t:
        return "high"
    if "ics" in t or "industrial" in t:
        return "medium"
    return "info"


def load_advisories():
    out = []
    cutoff = NOW - timedelta(days=ADVISORY_DAYS)
    for feed in ADVISORY_FEEDS:
        try:
            items = parse_feed(fetch(feed["url"]))
        except Exception as e:  # noqa: BLE001
            record(feed["name"], False, error=str(e)[:200])
            continue
        n = 0
        for it in items:
            if it["date"] and it["date"] < cutoff:
                continue
            if feed["src"] == "NCSC" and not ADVISORY_KEEP.search(it["title"] + " " + (it["summary"] or "")):
                continue  # skip NCSC press releases that aren't about threats
            out.append({
                "id": it["link"],
                "date": iso_day(it["date"]) or iso_day(NOW),
                "src": feed["src"],
                "vendor": feed["name"],
                "title": it["title"],
                "detail": clean_text(it["summary"], 300),
                "todo": "Read the advisory for affected products and mitigations.",
                "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", it["title"] + " " + (it["summary"] or "")))),
                "url": it["link"],
                "sev": advisory_severity(feed["src"], it["title"]),
            })
            n += 1
        record(feed["name"], True, n)
    return out


# ---------------------------------------------------------------- news

GROUPS = [
    ("Arrests, courts and policy", r"\b(arrest|sentenc|charged|indict|police|court|lawsuit|legislat|bill\b|regulat|sanction|fined|guilty|extradit|europol|fbi seiz|takedown)"),
    ("Breaches and ransomware", r"\b(ransomware|breach|leak|stole|stolen|extort|heist|exposed|data of|hacked|compromised)"),
    ("Exploited right now", r"\b(zero-day|0-day|exploit|actively|patch|vulnerab|flaw|cve-\d)"),
    ("Malware and campaigns", r"\b(malware|trojan|botnet|phish|campaign|apt\d*|spyware|stealer|backdoor|loader)"),
]
SKIP_NEWS = re.compile(r"(/offer/|/deals?/|sponsored|webinar)", re.I)


def group_for(title, summary):
    text = f"{title} {summary}".lower()
    for name, pat in GROUPS:
        if re.search(pat, text):
            return name
    return "Other news"


def norm_title(t):
    return re.sub(r"[^a-z0-9]+", "", t.lower())[:60]


def load_news():
    cutoff = NOW - timedelta(days=NEWS_DAYS)
    stories, seen = [], set()
    for feed in NEWS_FEEDS:
        try:
            items = parse_feed(fetch(feed["url"]))
        except Exception as e:  # noqa: BLE001
            record(feed["name"], False, error=str(e)[:200])
            continue
        n = 0
        for it in items:
            if it["date"] and it["date"] < cutoff:
                continue
            if SKIP_NEWS.search(it["link"]) or SKIP_NEWS.search(it["title"]):
                continue
            key = norm_title(it["title"])
            if key in seen or it["link"] in seen:
                continue
            seen.update({key, it["link"]})
            summary = clean_text(it["summary"], SNIPPET_CHARS)
            stories.append({
                "title": it["title"],
                "summary": summary,
                "source": feed["name"],
                "date": it["date"].isoformat() if it["date"] else None,
                "url": it["link"],
                "group": group_for(it["title"], summary),
            })
            n += 1
        record(feed["name"], True, n)
    stories.sort(key=lambda s: s["date"] or "", reverse=True)
    stories = stories[:NEWS_MAX]
    order = [g[0] for g in GROUPS] + ["Other news"]
    groups = [{"group": g, "items": [s for s in stories if s["group"] == g]} for g in order]
    return [g for g in groups if g["items"]]


# ---------------------------------------------------------------- main

def write_json(name, obj):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    text = json.dumps(obj, indent=1, ensure_ascii=False)
    old = path.read_text() if path.exists() else None
    if old != text:
        path.write_text(text)
        log(f"wrote {path.relative_to(ROOT)}")


def keep_previous(name, key):
    """If every source for a file failed, keep yesterday's data rather than blanking the page."""
    path = OUT_DIR / name
    if path.exists():
        try:
            return json.loads(path.read_text()).get(key, [])
        except json.JSONDecodeError:
            pass
    return []


def main():
    kev = load_kev()
    add_epss(kev)
    add_cvss(kev)
    for a in kev:
        a["sev"] = score_kev(a)
    advisories = load_advisories()
    alerts = kev + advisories
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    alerts.sort(key=lambda a: (a["date"], -sev_rank[a["sev"]]), reverse=True)
    alerts = alerts[:MAX_ALERTS]

    news = load_news()

    alert_sources_ok = any(s["ok"] for s in status if s["name"] in ("CISA KEV", *[f["name"] for f in ADVISORY_FEEDS]))
    news_sources_ok = any(s["ok"] for s in status if s["name"] in [f["name"] for f in NEWS_FEEDS])
    if not alert_sources_ok:
        alerts = keep_previous("alerts.json", "alerts")
    if not news_sources_ok:
        news = keep_previous("news.json", "groups")

    # Only touch alerts/news when content changed, so the workflow can skip empty commits.
    write_json("alerts.json", {"alerts": alerts})
    write_json("news.json", {"groups": news})
    write_json("meta.json", {"generated_at": NOW.isoformat(timespec="seconds"), "sources": status})

    failed = [s["name"] for s in status if not s["ok"]]
    if failed:
        log(f"Finished with failures: {', '.join(failed)}")
    if not alert_sources_ok and not news_sources_ok:
        sys.exit(1)  # everything failed: make the Actions run go red so you notice


if __name__ == "__main__":
    main()
