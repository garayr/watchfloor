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

# Cloudflare Radar attack data for the map. Needs the CLOUDFLARE_API_TOKEN secret.
RADAR_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"
RADAR_RANGE = "1d"               # last 24 hours
RADAR_EVERY_MIN = 60             # Radar data moves slowly; refresh hourly to avoid needless commits
RADAR_LAYERS = [
    {"key": "l7", "name": "Web application attacks", "path": "attacks/layer7/top/attacks"},
    {"key": "l3", "name": "Network DDoS attacks", "path": "attacks/layer3/top/attacks"},
]

# Phone notifications via ntfy (https://ntfy.sh). Set the NTFY_TOPIC secret to turn on.
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
NOTIFIED_FILE = ROOT / "cache" / "notified.json"
NOTIFY_MAX_PER_RUN = 5
DIGEST_FILE = ROOT / "cache" / "digest.json"
DIGEST_WEEKDAY = int(os.environ.get("DIGEST_WEEKDAY", "0"))      # 0 = Monday
DIGEST_HOUR_UTC = int(os.environ.get("DIGEST_HOUR_UTC", "7"))    # 7 UTC = 8am UK summer time, 7am winter


def dashboard_url():
    if os.environ.get("DASHBOARD_URL"):
        return os.environ["DASHBOARD_URL"]
    repo = os.environ.get("GITHUB_REPOSITORY", "")          # set automatically by GitHub Actions
    if "/" in repo:
        owner, name = repo.split("/", 1)
        return f"https://{owner.lower()}.github.io/{name}/"
    return None           # more than this in one run becomes a single summary message

# Approximate country locations (capital or population centre) for drawing arcs.
COUNTRY_LOC = {
    "AE": (24.5, 54.4), "AF": (34.5, 69.2), "AL": (41.3, 19.8), "AM": (40.2, 44.5), "AO": (-8.8, 13.2),
    "AR": (-34.6, -58.4), "AT": (48.2, 16.4), "AU": (-33.9, 151.2), "AZ": (40.4, 49.9), "BA": (43.9, 18.4),
    "BD": (23.8, 90.4), "BE": (50.8, 4.4), "BG": (42.7, 23.3), "BH": (26.2, 50.6), "BO": (-16.5, -68.1),
    "BR": (-23.5, -46.6), "BY": (53.9, 27.6), "CA": (43.7, -79.4), "CH": (46.9, 7.4), "CL": (-33.4, -70.6),
    "CM": (3.9, 11.5), "CN": (39.9, 116.4), "CO": (4.7, -74.1), "CR": (9.9, -84.1), "CY": (35.2, 33.4),
    "CZ": (50.1, 14.4), "DE": (50.1, 8.7), "DK": (55.7, 12.6), "DO": (18.5, -69.9), "DZ": (36.8, 3.1),
    "EC": (-0.2, -78.5), "EE": (59.4, 24.8), "EG": (30.0, 31.2), "ES": (40.4, -3.7), "ET": (9.0, 38.7),
    "FI": (60.2, 24.9), "FR": (48.9, 2.35), "GB": (51.5, -0.1), "GE": (41.7, 44.8), "GH": (5.6, -0.2),
    "GR": (38.0, 23.7), "GT": (14.6, -90.5), "HK": (22.3, 114.2), "HN": (14.1, -87.2), "HR": (45.8, 16.0),
    "HU": (47.5, 19.0), "ID": (-6.2, 106.8), "IE": (53.3, -6.3), "IL": (32.1, 34.8), "IN": (19.1, 72.9),
    "IQ": (33.3, 44.4), "IR": (35.7, 51.4), "IS": (64.1, -21.9), "IT": (41.9, 12.5), "JM": (18.0, -76.8),
    "JO": (31.9, 35.9), "JP": (35.7, 139.7), "KE": (-1.3, 36.8), "KG": (42.9, 74.6), "KH": (11.6, 104.9),
    "KR": (37.6, 127.0), "KP": (39.0, 125.75), "KW": (29.4, 48.0), "KZ": (43.2, 76.9), "LA": (18.0, 102.6),
    "LB": (33.9, 35.5), "LK": (6.9, 79.9), "LT": (54.7, 25.3), "LU": (49.6, 6.1), "LV": (56.9, 24.1),
    "LY": (32.9, 13.2), "MA": (33.6, -7.6), "MD": (47.0, 28.9), "ME": (42.4, 19.3), "MK": (42.0, 21.4),
    "MM": (16.8, 96.2), "MN": (47.9, 106.9), "MO": (22.2, 113.5), "MT": (35.9, 14.5), "MU": (-20.2, 57.5),
    "MX": (19.4, -99.1), "MY": (3.1, 101.7), "MZ": (-25.9, 32.6), "NG": (6.5, 3.4), "NI": (12.1, -86.3),
    "NL": (52.4, 4.9), "NO": (59.9, 10.8), "NP": (27.7, 85.3), "NZ": (-36.8, 174.8), "OM": (23.6, 58.4),
    "PA": (9.0, -79.5), "PE": (-12.0, -77.0), "PH": (14.6, 121.0), "PK": (24.9, 67.0), "PL": (52.2, 21.0),
    "PR": (18.5, -66.1), "PS": (31.9, 35.2), "PT": (38.7, -9.1), "PY": (-25.3, -57.6), "QA": (25.3, 51.5),
    "RO": (44.4, 26.1), "RS": (44.8, 20.5), "RU": (55.75, 37.6), "SA": (24.7, 46.7), "SC": (-4.6, 55.5),
    "SE": (59.3, 18.1), "SG": (1.35, 103.8), "SI": (46.1, 14.5), "SK": (48.1, 17.1), "SN": (14.7, -17.5),
    "SV": (13.7, -89.2), "SY": (33.5, 36.3), "TH": (13.75, 100.5), "TN": (36.8, 10.2), "TR": (41.0, 29.0),
    "TT": (10.7, -61.5), "TW": (25.0, 121.5), "TZ": (-6.8, 39.3), "UA": (50.45, 30.5), "UG": (0.3, 32.6),
    "US": (39.0, -77.5), "UY": (-34.9, -56.2), "UZ": (41.3, 69.3), "VE": (10.5, -66.9), "VN": (21.0, 105.8),
    "YE": (15.4, 44.2), "ZA": (-26.2, 28.0), "ZM": (-15.4, 28.3), "ZW": (-17.8, 31.0),
}

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
            "vendor_name": v.get("vendorProject", ""),
            "product": v.get("product", ""),
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
                "_text": f"{it['title']} {clean_text(it['summary'])}",
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


# ---------------------------------------------------------------- Cloudflare Radar

def radar_is_fresh():
    path = OUT_DIR / "attacks.json"
    if not path.exists():
        return False
    try:
        ts = json.loads(path.read_text()).get("generated_at")
        return bool(ts) and NOW - datetime.fromisoformat(ts) < timedelta(minutes=RADAR_EVERY_MIN - 5)
    except (json.JSONDecodeError, ValueError):
        return False


def radar_trend(path):
    """Hourly attack volume for the last 7 days, scaled 0-1 (1 = busiest hour)."""
    q = urllib.parse.urlencode({"dateRange": "7d", "aggInterval": "1h", "normalization": "MIN0_MAX", "format": "json"})
    try:
        data = json.loads(fetch(f"{RADAR_BASE}/{path}?{q}", headers={"Authorization": f"Bearer {RADAR_TOKEN}"}, tries=2))
        result = data.get("result") or {}
        serie = next((v for k, v in result.items() if k.startswith("serie")), None) or {}
        ts, vals = serie.get("timestamps") or [], serie.get("values") or []
        points = []
        for t, v in zip(ts, vals):
            try:
                points.append((t, float(v)))
            except (TypeError, ValueError):
                continue
        if len(points) < 48:
            return None
        values = [v for _, v in points]
        last_day, before = values[-24:], values[:-24]
        change = None
        if before and sum(before) > 0:
            change = round((sum(last_day) / len(last_day)) / (sum(before) / len(before)) * 100 - 100, 1)
        return {"t": [t for t, _ in points], "v": [round(v, 4) for v in values], "change": change}
    except Exception as e:  # noqa: BLE001
        log(f"  Radar trend failed for {path}: {e}")
        return None


def load_radar():
    """Top origin -> target attack pairs from Cloudflare Radar.
    Values are each pair's share (%) of all attacks Cloudflare saw in the period."""
    if not RADAR_TOKEN:
        log("SKIP Cloudflare Radar: no CLOUDFLARE_API_TOKEN secret set")
        return None
    if radar_is_fresh():
        log("SKIP Cloudflare Radar: data is less than an hour old")
        return None
    layers, errors, unknown = [], [], set()
    for layer in RADAR_LAYERS:
        q = urllib.parse.urlencode({"dateRange": RADAR_RANGE, "limit": 25, "format": "json"})
        try:
            data = json.loads(fetch(f"{RADAR_BASE}/{layer['path']}?{q}",
                                    headers={"Authorization": f"Bearer {RADAR_TOKEN}"}, tries=2))
            if not data.get("success", True):
                raise RuntimeError("; ".join(e.get("message", "") for e in data.get("errors", [])) or "request failed")
            rows = (data.get("result") or {}).get("top_0") or []
        except Exception as e:  # noqa: BLE001
            errors.append(f"{layer['name']}: {str(e)[:150]}")
            continue
        pairs = []
        for r in rows:
            o = (r.get("originCountryAlpha2") or r.get("origin_country_alpha2") or "").upper()
            t = (r.get("targetCountryAlpha2") or r.get("target_country_alpha2") or "").upper()
            try:
                share = float(r.get("value", 0))
            except (TypeError, ValueError):
                continue
            if o not in COUNTRY_LOC or t not in COUNTRY_LOC:
                unknown.update(c for c in (o, t) if c and c not in COUNTRY_LOC)
                continue
            if o == t or share <= 0:
                continue  # an arc needs two different places
            pairs.append({
                "from": {"code": o, "name": r.get("originCountryName") or o, "lat": COUNTRY_LOC[o][0], "lon": COUNTRY_LOC[o][1]},
                "to": {"code": t, "name": r.get("targetCountryName") or t, "lat": COUNTRY_LOC[t][0], "lon": COUNTRY_LOC[t][1]},
                "share": round(share, 3),
            })
        layers.append({"key": layer["key"], "name": layer["name"], "pairs": pairs})
    if unknown:
        log(f"  Radar: no map location for {', '.join(sorted(unknown))} (add them to COUNTRY_LOC)")
    for layer, cfg in zip(layers, [l for l in RADAR_LAYERS if l["name"] in {x["name"] for x in layers}]):
        trend = radar_trend(cfg["path"].replace("/top/attacks", "/timeseries"))
        if trend:
            layer["trend"] = trend
    ok = any(l["pairs"] for l in layers)
    record("Cloudflare Radar", ok, sum(len(l["pairs"]) for l in layers), "; ".join(errors) or None)
    if not ok:
        return None
    return {"generated_at": NOW.isoformat(timespec="seconds"), "range": RADAR_RANGE,
            "source": "Cloudflare Radar", "layers": layers}


# ---------------------------------------------------------------- phone notifications

def post_json(url, payload, timeout=20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def notify_new_critical(alerts):
    """Send one push per newly Critical alert. The first run only records what's
    already there, so you don't get a flood of old alerts when you switch this on."""
    if not NTFY_TOPIC:
        return
    critical = [a for a in alerts if a.get("sev") == "critical"]
    first_run = not NOTIFIED_FILE.exists()
    seen = []
    if not first_run:
        try:
            seen = json.loads(NOTIFIED_FILE.read_text()).get("ids", [])
        except json.JSONDecodeError:
            seen = []
    new = [a for a in critical if a["id"] not in seen]

    sent, failed = 0, 0
    if first_run:
        log(f"ntfy: first run, recording {len(new)} existing critical alerts without notifying")
    else:
        messages = []
        for a in new[:NOTIFY_MAX_PER_RUN]:
            lines = [a.get("vendor", ""), a.get("detail", "")]
            if a.get("todo"):
                lines.append(f"What to do: {a['todo']}")
            if a.get("due"):
                lines.append(f"US federal deadline: {a['due']}")
            messages.append({
                "title": f"Critical: {a['title']}"[:150],
                "message": "\n".join(x for x in lines if x)[:900],
                "click": a.get("url"),
                "tags": ["rotating_light"],
            })
        if len(new) > NOTIFY_MAX_PER_RUN:
            extra = len(new) - NOTIFY_MAX_PER_RUN
            messages.append({"title": f"{extra} more critical alert{'s' if extra > 1 else ''}",
                             "message": "Open Watchfloor to see them all.", "tags": ["rotating_light"]})
        for m in messages:
            m.update({"topic": NTFY_TOPIC, "priority": 4})
            if not m.get("click"):
                m.pop("click", None)
            try:
                post_json(NTFY_SERVER, m)
                sent += 1
            except Exception as e:  # noqa: BLE001
                failed += 1
                log(f"  ntfy send failed: {e}")
        if failed and not sent:
            # nothing got through: don't mark these as sent, so the next run retries
            record("Phone alerts", False, 0, f"{failed} notifications failed to send")
            return
        record("Phone alerts", True, sent)

    ids = [a["id"] for a in critical] + [i for i in seen if i not in {a["id"] for a in critical}]
    NOTIFIED_FILE.parent.mkdir(parents=True, exist_ok=True)
    NOTIFIED_FILE.write_text(json.dumps({"ids": ids[:500]}, indent=1))


# ---------------------------------------------------------------- linking news to alerts

GENERIC_WORDS = {
    "server", "servers", "multiple", "products", "product", "enterprise", "edition", "community", "windows",
    "linux", "kernel", "management", "manager", "appliance", "appliances", "gateway", "firewall", "web",
    "client", "platform", "security", "cloud", "network", "service", "services", "system", "systems",
    "office", "center", "centre", "console", "software", "application", "applications", "plugin", "the",
}


def product_words(product):
    return {w for w in re.findall(r"[a-z0-9][a-z0-9\-]{3,}", product.lower()) if w not in GENERIC_WORDS}


def link_news(alerts, groups):
    """Tag alerts that the news is talking about, and news that mentions an alert.
    A story matches if it names the CVE, or names both the vendor and a distinctive
    product word (for example "Citrix" and "NetScaler")."""
    stories = [s for g in groups for s in g["items"]]
    for s in stories:
        s["alerts"] = []
    linked = 0
    for a in alerts:
        matches = []
        vendor = (a.get("vendor_name") or "").lower()
        words = product_words(a.get("product") or "")
        for s in stories:
            text = s["_text"].lower()
            hit = any(c.lower() in text for c in a.get("cves", []))
            if not hit and vendor and len(vendor) > 2 and words:
                hit = re.search(rf"\b{re.escape(vendor)}\b", text) and any(re.search(rf"\b{re.escape(w)}\b", text) for w in words)
            if hit:
                matches.append(s)
        if matches:
            linked += 1
            a["news"] = [{"title": s["title"], "url": s["url"], "source": s["source"], "date": s["date"]}
                         for s in sorted(matches, key=lambda s: s["date"] or "", reverse=True)[:3]]
            for s in matches:
                if a["id"] not in s["alerts"] and len(s["alerts"]) < 4:
                    s["alerts"].append(a["id"])
    for s in stories:
        s.pop("_text", None)
        if not s["alerts"]:
            s.pop("alerts")
    log(f"linked {linked} alerts to news stories")


# ---------------------------------------------------------------- weekly digest

def send_digest(alerts, groups):
    """A Monday-morning phone summary of the past week."""
    if not NTFY_TOPIC or NOW.weekday() != DIGEST_WEEKDAY or NOW.hour < DIGEST_HOUR_UTC:
        return
    week = NOW.strftime("%G-W%V")
    try:
        last = json.loads(DIGEST_FILE.read_text()).get("week") if DIGEST_FILE.exists() else None
    except json.JSONDecodeError:
        last = None
    if last == week:
        return
    since = (NOW - timedelta(days=7)).strftime("%Y-%m-%d")
    recent = [a for a in alerts if a["date"] >= since]
    crit = [a for a in recent if a["sev"] == "critical"]
    high = [a for a in recent if a["sev"] == "high"]
    lines = [f"{len(crit)} critical and {len(high)} high alerts in the last 7 days."]
    if crit:
        lines.append("")
        lines.append("Critical:")
        lines += [f"- {a['title']}" for a in crit[:5]]
        if len(crit) > 5:
            lines.append(f"- and {len(crit) - 5} more")
    in_news = [a for a in recent if a.get("news") and a["sev"] in ("critical", "high")]
    if in_news:
        lines.append("")
        lines.append("Most talked about:")
        lines += [f"- {a['title']}" for a in in_news[:3]]
    top = sorted((s for g in groups for s in g["items"]), key=lambda s: s["date"] or "", reverse=True)[:3]
    if top:
        lines.append("")
        lines.append("Headlines:")
        lines += [f"- {s['title']}" for s in top]
    msg = {"topic": NTFY_TOPIC, "title": f"Your week in cyber, to {NOW.strftime('%-d %b')}",
           "message": "\n".join(lines)[:3500], "priority": 3, "tags": ["newspaper"]}
    url = dashboard_url()
    if url:
        msg["click"] = url
    try:
        post_json(NTFY_SERVER, msg)
        DIGEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        DIGEST_FILE.write_text(json.dumps({"week": week, "sent_at": NOW.isoformat(timespec="seconds")}))
        record("Weekly digest", True, 1)
    except Exception as e:  # noqa: BLE001
        record("Weekly digest", False, 0, str(e)[:200])


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
    link_news(alerts, news)
    radar = load_radar()
    if any(s["ok"] for s in status if s["name"] == "CISA KEV"):
        notify_new_critical(alerts)
    send_digest(alerts, news)

    alert_sources_ok = any(s["ok"] for s in status if s["name"] in ("CISA KEV", *[f["name"] for f in ADVISORY_FEEDS]))
    news_sources_ok = any(s["ok"] for s in status if s["name"] in [f["name"] for f in NEWS_FEEDS])
    if not alert_sources_ok:
        alerts = keep_previous("alerts.json", "alerts")
    if not news_sources_ok:
        news = keep_previous("news.json", "groups")

    # Only touch alerts/news when content changed, so the workflow can skip empty commits.
    write_json("alerts.json", {"alerts": alerts})
    write_json("news.json", {"groups": news})
    if radar:
        write_json("attacks.json", radar)
    write_json("meta.json", {"generated_at": NOW.isoformat(timespec="seconds"), "sources": status})

    failed = [s["name"] for s in status if not s["ok"]]
    if failed:
        log(f"Finished with failures: {', '.join(failed)}")
    if not alert_sources_ok and not news_sources_ok:
        sys.exit(1)  # everything failed: make the Actions run go red so you notice


if __name__ == "__main__":
    main()
