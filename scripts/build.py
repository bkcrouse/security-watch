#!/usr/bin/env python3
"""Security Watch builder.

Pulls exploited and critical vulnerabilities from CISA KEV, NVD, the GitHub
Advisory Database (including malware advisories) and FIRST EPSS, scores them,
applies hand-written overrides and your watchlist, and writes a static site:

    <out>/data.json   everything the page renders
    <out>/feed.xml    RSS of the "act" and "watch" tiers
    <out>/*           the static front end copied from web/

Standard library only, so it runs anywhere Python 3.10+ does.

    python scripts/build.py --out site                    # live feeds
    python scripts/build.py --out site --fixtures tests/fixtures   # offline
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
GH_API = "https://api.github.com"
NPM_DL = "https://api.npmjs.org/downloads/point/last-month/"
PYPI_DL = "https://pypistats.org/api/packages/{}/recent"

KEV_DAYS = 30            # KEV additions shown
CRITICAL_DAYS = 7        # CVSS 9+ window
MALWARE_DAYS = 30        # malicious-package window
MALWARE_MIN_DOWNLOADS = 50_000
MAX_EXACT_VERSIONS = 12  # keep data.json small; summarise the rest
REFRESH_MINUTES = 15

# SW_NOW pins the clock so fixture builds are reproducible.
NOW = (dt.datetime.fromisoformat(os.environ["SW_NOW"].replace("Z", "+00:00"))
       if os.environ.get("SW_NOW") else dt.datetime.now(dt.timezone.utc))

# Products whose flaws hit a lot of organisations. Matched as lowercase
# substrings against "vendor product".
WIDESPREAD = [
    "microsoft", "windows", "exchange", "sharepoint", "office", "azure", "entra",
    "apple", "ios", "macos", "google chrome", "chromium", "android",
    "linux kernel", "cisco", "fortinet", "fortios", "fortigate", "palo alto",
    "paloaltonetworks", "pan-os", "ivanti", "citrix", "netscaler", "vmware",
    "esxi", "oracle", "sap", "atlassian", "confluence", "jira", "adobe",
    "mozilla", "firefox", "php", "apache", "tomcat", "nginx", "openssl",
    "openssh", "jenkins", "gitlab", "github", "kubernetes", "docker", "f5",
    "big-ip", "sonicwall", "juniper", "veeam", "zimbra", "progress", "moveit",
    "solarwinds", "log4j", "spring", "next", "react", "django", "laravel",
    "wordpress core", "sophos", "checkpoint", "check point", "zyxel",
    "openvpn", "samba", "sudo", "glibc", "git", "golang", "node.js", "nodejs",
]
# Products that usually sit on the internet edge.
EDGE = [
    "vpn", "gateway", "firewall", "fortios", "fortigate", "pan-os", "globalprotect",
    "netscaler", "citrix adc", "big-ip", "ivanti connect", "pulse", "sonicwall",
    "exchange", "edge", "sslvpn", "asa", "ftd", "orchestrator", "load balancer",
]


# --------------------------------------------------------------------------
# HTTP with retries and a small on-disk cache
# --------------------------------------------------------------------------

def http_json(url: str, headers: dict | None = None, ttl: int = 0, tries: int = 4):
    """GET JSON. ttl>0 caches the response on disk for that many seconds."""
    cache_file = None
    if ttl:
        cache_file = CACHE / "http" / (hashlib.sha256(url.encode()).hexdigest() + ".json")
        if cache_file.exists() and time.time() - cache_file.stat().st_mtime < ttl:
            return json.loads(cache_file.read_text())

    hdrs = {"User-Agent": "security-watch (+https://github.com)", "Accept": "application/json"}
    hdrs.update(headers or {})
    delay = 2.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                data = json.loads(body)
                link = r.headers.get("Link", "")
            if cache_file:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_bytes(body)
            http_json.last_link = link
            return data
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < tries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise


http_json.last_link = ""


def next_link(link_header: str) -> str | None:
    m = re.search(r'<([^>]+)>;\s*rel="next"', link_header or "")
    return m.group(1) if m else None


def gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def nvd_headers() -> dict:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def nvd_pause():
    # NVD: 5 requests / 30 s without a key, 50 / 30 s with one.
    time.sleep(0.7 if os.environ.get("NVD_API_KEY") else 6.5)


# --------------------------------------------------------------------------
# Fetchers (each returns raw upstream JSON so fixtures can stand in)
# --------------------------------------------------------------------------

def fetch_kev() -> dict:
    return http_json(KEV_URL, ttl=10 * 60)


def nvd_ts(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_nvd_critical() -> list[dict]:
    start = NOW - dt.timedelta(days=CRITICAL_DAYS)
    out: dict[str, dict] = {}
    for sev_param in ("cvssV3Severity", "cvssV4Severity"):
        idx = 0
        while True:
            q = urllib.parse.urlencode({
                "pubStartDate": nvd_ts(start), "pubEndDate": nvd_ts(NOW),
                sev_param: "CRITICAL", "resultsPerPage": 2000, "startIndex": idx,
            })
            data = http_json(f"{NVD_URL}?{q}", headers=nvd_headers())
            for v in data.get("vulnerabilities", []):
                out[v["cve"]["id"]] = v["cve"]
            idx += data.get("resultsPerPage", 0)
            nvd_pause()
            if not data.get("resultsPerPage") or idx >= data.get("totalResults", 0):
                break
    return list(out.values())


def fetch_nvd_one(cve_id: str) -> dict | None:
    """Single CVE; cached 6 h so the 15-minute runs stay cheap."""
    cache_file = CACHE / "nvd" / f"{cve_id}.json"
    if cache_file.exists() and time.time() - cache_file.stat().st_mtime < 6 * 3600:
        return json.loads(cache_file.read_text()) or None
    try:
        data = http_json(f"{NVD_URL}?cveId={cve_id}", headers=nvd_headers())
        nvd_pause()
    except Exception as e:  # noqa: BLE001 - one bad CVE shouldn't kill the build
        print(f"warn: NVD lookup {cve_id} failed: {e}", file=sys.stderr)
        return None
    vulns = data.get("vulnerabilities") or []
    cve = vulns[0]["cve"] if vulns else {}
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cve))
    return cve or None


def fetch_ghsa(kind: str, days: int, severity: str | None) -> list[dict]:
    since = (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    params = {"type": kind, "published": f">={since}", "per_page": 100}
    if severity:
        params["severity"] = severity
    url = f"{GH_API}/advisories?{urllib.parse.urlencode(params)}"
    out, pages = [], 0
    while url and pages < 20:
        out.extend(http_json(url, headers=gh_headers()))
        url = next_link(http_json.last_link)
        pages += 1
    return out


def fetch_epss(cves: list[str]) -> dict[str, dict]:
    scores: dict[str, dict] = {}
    for i in range(0, len(cves), 100):
        chunk = ",".join(cves[i:i + 100])
        try:
            data = http_json(f"{EPSS_URL}?cve={chunk}", ttl=6 * 3600)
        except Exception as e:  # noqa: BLE001
            print(f"warn: EPSS failed: {e}", file=sys.stderr)
            continue
        for row in data.get("data", []):
            scores[row["cve"]] = {"epss": float(row["epss"]), "epssPct": float(row["percentile"])}
    return scores


_NPM_BULK: dict[str, int] = {}


def prefetch_npm_downloads(names: list[str]) -> None:
    """npm's bulk endpoint takes up to 128 unscoped names per call."""
    plain = sorted({n for n in names if not n.startswith("@") and n not in _NPM_BULK})
    for i in range(0, len(plain), 128):
        chunk = plain[i:i + 128]
        try:
            d = http_json(NPM_DL + ",".join(urllib.parse.quote(n, safe="") for n in chunk), ttl=24 * 3600)
        except Exception as e:  # noqa: BLE001
            print(f"warn: npm bulk downloads failed: {e}", file=sys.stderr)
            continue
        for n in chunk:
            row = d.get(n) if isinstance(d, dict) else None
            _NPM_BULK[n] = int((row or {}).get("downloads") or 0)


def monthly_downloads(ecosystem: str, name: str) -> int | None:
    if ecosystem == "npm" and name in _NPM_BULK:
        return _NPM_BULK[name]
    try:
        if ecosystem == "npm":
            d = http_json(NPM_DL + urllib.parse.quote(name, safe="@/"), ttl=24 * 3600)
            return int(d.get("downloads") or 0)
        if ecosystem == "pip":
            d = http_json(PYPI_DL.format(urllib.parse.quote(name.lower())), ttl=24 * 3600)
            return int((d.get("data") or {}).get("last_month") or 0)
    except Exception:  # noqa: BLE001 - unknown/removed packages 404
        return None
    return None


# --------------------------------------------------------------------------
# Normalisers
# --------------------------------------------------------------------------

CASING = {
    "php": "PHP", "pan-os": "PAN-OS", "paloaltonetworks": "Palo Alto Networks", "ios": "iOS",
    "macos": "macOS", "ipados": "iPadOS", "fortios": "FortiOS", "fortinet": "Fortinet",
    "vmware": "VMware", "esxi": "ESXi", "sap": "SAP", "f5": "F5", "big-ip": "BIG-IP",
    "openssl": "OpenSSL", "openssh": "OpenSSH", "gitlab": "GitLab", "github": "GitHub",
    "wordpress": "WordPress", "netscaler": "NetScaler", "sonicwall": "SonicWall",
    "ibm": "IBM", "hp": "HP", "hpe": "HPE", "d-link": "D-Link", "tp-link": "TP-Link",
    "totolink": "TOTOLINK", "jetbrains": "JetBrains", "teamcity": "TeamCity",
    "phpmyadmin": "phpMyAdmin", "nodejs": "Node.js", "postgresql": "PostgreSQL", "mysql": "MySQL",
}


def pretty(s: str) -> str:
    """cpe-style 'palo_alto_networks' -> 'Palo Alto Networks', with known casings."""
    s = (s or "").replace("\\", "").replace("_", " ").strip()
    if not s:
        return ""
    if s.lower() in CASING:
        return CASING[s.lower()]
    return " ".join(CASING.get(w.lower()) or
                    (w if (w.isupper() or any(c.isdigit() for c in w)) else w.capitalize())
                    for w in s.split())


def first_en(descs: list[dict]) -> str:
    for d in descs or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def clip(s: str, n: int = 700) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def title_from(desc: str) -> str:
    first = re.split(r"(?<=[.!?])\s", desc.strip(), maxsplit=1)[0]
    return clip(first, 140)


def nvd_cvss(cve: dict) -> tuple[float | None, str, str]:
    m = cve.get("metrics", {})
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        rows = m.get(key) or []
        if rows:
            primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
            d = primary.get("cvssData", {})
            return d.get("baseScore"), (d.get("baseSeverity") or "").upper(), ver
    return None, "", ""


def nvd_products(cve: dict) -> list[dict]:
    """Group vulnerable CPE matches into {vendor, product, affected, ranges}."""
    groups: dict[tuple[str, str], dict] = {}
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, version = pretty(parts[3]), pretty(parts[4]), parts[5]
                key = (vendor.lower(), product.lower())   # case-insensitive dedupe
                g = groups.setdefault(key, {"vendor": vendor, "product": product,
                                            "affected": [], "fixed": [], "ranges": [], "exact": []})
                lo = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                hi = m.get("versionEndExcluding") or m.get("versionEndIncluding")
                if lo or hi:
                    rng = {"lo": lo or "", "loIncl": bool(m.get("versionStartIncluding")),
                           "hi": hi or "", "hiIncl": bool(m.get("versionEndIncluding"))}
                    if rng not in g["ranges"]:
                        g["ranges"].append(rng)
                        if lo and hi:
                            txt = f"{lo} to {'through' if rng['hiIncl'] else 'before'} {hi}"
                        elif hi:
                            txt = f"{'through' if rng['hiIncl'] else 'before'} {hi}"
                        else:
                            txt = f"{lo} and later"
                        g["affected"].append(txt)
                        if m.get("versionEndExcluding") and hi not in g["fixed"]:
                            g["fixed"].append(hi)
                elif version not in ("*", "-", ""):
                    if version not in g["exact"]:
                        g["exact"].append(version)
    out = []
    for g in groups.values():
        if len(g["exact"]) > MAX_EXACT_VERSIONS:
            n = len(g["exact"])
            g["affected"].append(f"{n} specific versions ({g['exact'][0]} … {g['exact'][-1]})")
            g["exact"] = g["exact"][:MAX_EXACT_VERSIONS]
        elif g["exact"]:
            g["affected"].extend(g["exact"])
        out.append(g)
    return out


def from_nvd(cve: dict) -> dict:
    desc = first_en(cve.get("descriptions"))
    score, sev, ver = nvd_cvss(cve)
    products = nvd_products(cve)
    return {
        "id": cve["id"],
        "title": title_from(desc),
        "description": clip(desc),
        "published": cve.get("published", ""),
        "score": score, "severity": sev, "cvssVersion": ver,
        "products": products,
        "vendor": products[0]["vendor"] if products else "",
        "product": products[0]["product"] if products else "",
        "sources": ["NVD"],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }


def ghsa_score(adv: dict) -> float | None:
    sev = adv.get("cvss_severities") or {}
    for k in ("cvss_v4", "cvss_v3"):
        s = (sev.get(k) or {}).get("score")
        if s:
            return float(s)
    s = (adv.get("cvss") or {}).get("score")
    return float(s) if s else None


def from_ghsa(adv: dict) -> dict:
    products = []
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        fixed = v.get("first_patched_version")
        if isinstance(fixed, dict):
            fixed = fixed.get("identifier")
        products.append({
            "vendor": pkg.get("ecosystem", ""), "product": pkg.get("name", ""),
            "affected": [v["vulnerable_version_range"]] if v.get("vulnerable_version_range") else [],
            "fixed": [fixed] if fixed else [], "ranges": [], "exact": [],
        })
    cve = adv.get("cve_id")
    rec = {
        "id": cve or adv["ghsa_id"],
        "ghsa": adv["ghsa_id"],
        "title": clip(adv.get("summary") or "", 160),
        "description": clip(adv.get("description") or ""),
        "published": adv.get("published_at", ""),
        "score": ghsa_score(adv),
        "severity": (adv.get("severity") or "").upper(),
        "cvssVersion": "",
        "products": products,
        "vendor": products[0]["vendor"] if products else "",
        "product": products[0]["product"] if products else "",
        "sources": ["GitHub"],
        "url": adv.get("html_url") or f"https://github.com/advisories/{adv['ghsa_id']}",
    }
    epss = adv.get("epss")
    if isinstance(epss, list):          # tolerate either shape
        epss = epss[0] if epss else None
    if isinstance(epss, dict) and epss.get("percentage") is not None:
        rec["epss"] = float(epss["percentage"])
        rec["epssPct"] = float(epss.get("percentile") or 0)
    return rec


# --------------------------------------------------------------------------
# Merge, enrich, score
# --------------------------------------------------------------------------

def merge(base: dict, extra: dict) -> dict:
    """Fill gaps in base from extra; union sources and products."""
    for k, v in extra.items():
        if k == "sources":
            base["sources"] = sorted(set(base.get("sources", [])) | set(v))
        elif k == "products":
            base.setdefault("products", [])
            by_key = {(p["vendor"].lower(), p["product"].lower()): p for p in base["products"]}
            for p in v:
                cur = by_key.get((p["vendor"].lower(), p["product"].lower()))
                if cur is None:
                    base["products"].append(p)
                else:  # same product from another source: keep the richer version data
                    for f in ("affected", "fixed", "ranges", "exact"):
                        if not cur.get(f) and p.get(f):
                            cur[f] = p[f]
        elif base.get(k) in (None, "", [], 0) and v not in (None, ""):
            base[k] = v
    return base


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def watch_terms(watchlist: list) -> list[str]:
    terms = []
    for w in watchlist:
        if isinstance(w, str):
            terms.append(w.lower())
        else:
            terms.append(" ".join(x for x in (w.get("vendor"), w.get("product")) if x).lower())
    return [t for t in terms if t]


def product_text(rec: dict) -> str:
    bits = [rec.get("vendor", ""), rec.get("product", "")]
    for p in rec.get("products", []):
        bits += [p.get("vendor", ""), p.get("product", "")]
    return " ".join(bits).lower()


def haystack(rec: dict) -> str:
    return (product_text(rec) + " " + rec.get("title", "")).lower()


# Common English words that only count when they are the product name itself.
AMBIGUOUS = {"next", "react", "spring", "git", "office", "edge", "sap", "progress",
             "sudo", "asa", "pulse", "gateway", "firewall", "vpn", "orchestrator"}


def mentions(words: list[str], rec: dict) -> bool:
    prod, hay = product_text(rec), haystack(rec)
    return any(re.search(rf"\b{re.escape(w)}\b", prod if w in AMBIGUOUS else hay) for w in words)


def score(rec: dict, watch: list[str]) -> dict:
    hay = haystack(rec)
    why, p = [], 0.0

    if rec.get("exploited"):
        p += 60; why.append("Exploited in the wild")
    if rec.get("ransomware"):
        p += 15; why.append("Used by ransomware gangs")
    if rec.get("kind") == "malware":
        p += 50; why.append("Malicious code in a popular package")

    e = rec.get("epss")
    if e is not None:
        p += 40 * e
        if e >= 0.10:
            why.append(f"High chance of exploitation (EPSS {round(e * 100)}%)")

    s = rec.get("score")
    if s:
        p += 2 * s
        if s >= 9:
            why.append(f"Critical severity (CVSS {s:.1f})")

    rec["widespread"] = mentions(WIDESPREAD, rec)
    if rec["widespread"]:
        p += 12; why.append("Widely used product")
    if mentions(EDGE, rec):
        p += 6; why.append("Usually internet-facing")

    due = rec.get("kevDue")
    if due:
        days_left = (dt.date.fromisoformat(due) - NOW.date()).days
        if days_left <= 7:
            p += 10; why.append("CISA deadline within a week")

    rec["watched"] = any(t in hay for t in watch)
    if rec["watched"]:
        p += 40; why.insert(0, "On your watchlist")

    if "wordpress" in hay and ("plugin" in hay or rec.get("vendor", "").lower() not in ("wordpress",)):
        p *= 0.4; why.append("WordPress plugin (ranked lower)")

    try:
        age = (NOW.date() - dt.date.fromisoformat(rec["date"])).days
    except (KeyError, ValueError):
        age = 0
    p -= min(age, 15)

    if rec.get("pinned"):
        p += 25

    rec["priority"] = round(max(p, 0), 1)
    rec["why"] = why
    rec["hasFix"] = any(pr.get("fixed") for pr in rec.get("products", []))
    if rec.get("exploited") or rec.get("kind") == "malware" or (rec["watched"] and (s or 0) >= 9):
        rec["tier"] = "act"
    elif rec["priority"] >= 40 or rec["watched"]:
        rec["tier"] = "watch"
    else:
        rec["tier"] = "fyi"
    return rec


def build(raw: dict, overrides: dict, watchlist: list) -> dict:
    records: dict[str, dict] = {}
    kev_cut = (NOW - dt.timedelta(days=KEV_DAYS)).date().isoformat()

    # 1. CISA KEV (last 30 days)
    for k in raw["kev"].get("vulnerabilities", []):
        if k.get("dateAdded", "") < kev_cut:
            continue
        records[k["cveID"]] = {
            "id": k["cveID"],
            "title": k.get("vulnerabilityName", ""),
            "description": clip(k.get("shortDescription", "")),
            "published": k.get("dateAdded", ""),
            "vendor": k.get("vendorProject", ""), "product": k.get("product", ""),
            "products": [{"vendor": k.get("vendorProject", ""), "product": k.get("product", ""),
                          "affected": [], "fixed": [], "ranges": [], "exact": []}],
            "exploited": True, "kevAdded": k.get("dateAdded", ""), "kevDue": k.get("dueDate", ""),
            "ransomware": k.get("knownRansomwareCampaignUse", "").lower() == "known",
            "action": k.get("requiredAction", ""),
            "sources": ["CISA KEV"],
            "url": f"https://nvd.nist.gov/vuln/detail/{k['cveID']}",
        }

    # 2. NVD critical (last 7 days) + NVD details for KEV entries
    for cve in raw["nvd"]:
        r = from_nvd(cve)
        records[r["id"]] = merge(records.get(r["id"], {}), r) if r["id"] in records else r
    for cid, rec in records.items():
        if "NVD" not in rec["sources"] and cid.startswith("CVE-"):
            cve = raw["nvd_lookup"](cid)
            if cve:
                merge(rec, from_nvd(cve))

    # 3. GitHub reviewed advisories, critical (last 7 days)
    for adv in raw["ghsa"]:
        r = from_ghsa(adv)
        if r["id"] in records:
            merge(records[r["id"]], r)
        else:
            records[r["id"]] = r

    # 4. Malicious packages with real reach
    for adv in raw["malware"]:
        hits = []
        for v in adv.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            eco, name = pkg.get("ecosystem"), pkg.get("name")
            if eco in ("npm", "pip") and name:
                n = raw["downloads"](eco, name)
                if n and n >= MALWARE_MIN_DOWNLOADS:
                    hits.append(n)
        if hits:
            r = from_ghsa(adv)
            r.update(kind="malware", exploited=True, monthlyDownloads=max(hits),
                     severity=r["severity"] or "CRITICAL")
            records[r["id"]] = r

    # 5. EPSS for every CVE we hold
    cves = sorted(i for i in records if i.startswith("CVE-"))
    epss = raw["epss"](cves)
    for cid, sc in epss.items():
        records[cid].update(sc)

    # 6. Hand-written overrides: patches, extra items, suppressions
    for cid in overrides.get("suppress", []):
        records.pop(cid, None)
    for cid, patch in overrides.get("patch", {}).items():
        if cid in records:
            records[cid].update(patch)
    for item in overrides.get("items", []):
        base = {"products": [], "sources": [], "description": "", "title": "", "published": ""}
        base.update(item)
        records[item["id"]] = merge(records.get(item["id"], {}), base) if item["id"] in records else base

    # 7. Defaults, dates, score
    watch = watch_terms(watchlist)
    for rec in records.values():
        for k, v in (("exploited", False), ("ransomware", False), ("kevAdded", ""), ("kevDue", ""),
                     ("kind", ""), ("action", ""), ("pinned", False), ("score", None),
                     ("severity", ""), ("cvssVersion", ""), ("vendor", ""), ("product", "")):
            rec.setdefault(k, v)
        rec["date"] = (rec.get("kevAdded") or rec.get("published") or "")[:10]
        score(rec, watch)

    items = sorted(records.values(), key=lambda r: (-r["priority"], r["id"]))

    today = NOW.date().isoformat()
    week_ago = (NOW - dt.timedelta(days=7)).date().isoformat()
    day_ago = NOW - dt.timedelta(hours=24)

    def published_dt(r):
        try:
            return dt.datetime.fromisoformat(r["published"].replace("Z", "+00:00")).replace(
                tzinfo=dt.timezone.utc) if r["published"] else None
        except ValueError:
            return None

    upcoming = sorted((r for r in items if r["kevDue"] and r["kevDue"] >= today),
                      key=lambda r: r["kevDue"])
    return {
        "generated": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "refreshMinutes": REFRESH_MINUTES,
        "summary": {
            "actNow": sum(r["tier"] == "act" for r in items),
            "exploited7d": sum(bool(r["kevAdded"]) and r["kevAdded"] >= week_ago for r in items),
            "critical24h": sum((r["score"] or 0) >= 9 and (published_dt(r) or NOW - dt.timedelta(days=9)) >= day_ago
                               for r in items),
            "watched": sum(r["watched"] for r in items),
            "nextDue": upcoming[0]["kevDue"] if upcoming else "",
        },
        "deadlines": [{"id": r["id"], "due": r["kevDue"], "vendor": r["vendor"], "product": r["product"]}
                      for r in upcoming[:12]],
        "windows": {"kevDays": KEV_DAYS, "criticalDays": CRITICAL_DAYS,
                    "malwareDays": MALWARE_DAYS, "malwareMinDownloads": MALWARE_MIN_DOWNLOADS},
        "items": items,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_rss(data: dict, path: Path, site_url: str):
    rows = [r for r in data["items"] if r["tier"] in ("act", "watch")][:60]
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0"><channel>',
           "<title>Security Watch</title>",
           f"<link>{escape(site_url)}</link>",
           "<description>Exploited and critical vulnerabilities</description>",
           f"<lastBuildDate>{format_datetime(NOW)}</lastBuildDate>"]
    for r in rows:
        try:
            pub = format_datetime(dt.datetime.fromisoformat(r["date"]).replace(tzinfo=dt.timezone.utc))
        except ValueError:
            pub = format_datetime(NOW)
        desc = " · ".join(r["why"]) + ("\n\n" + r.get("note", "") if r.get("note") else "") + "\n\n" + r["description"]
        out += ["<item>",
                f"<title>{escape('[' + r['tier'].upper() + '] ' + r['id'] + ': ' + r['title'])}</title>",
                f"<link>{escape(r['url'])}</link>",
                f"<guid isPermaLink=\"false\">{escape(r['id'])}</guid>",
                f"<pubDate>{pub}</pubDate>",
                f"<description>{escape(desc)}</description>",
                "</item>"]
    out.append("</channel></rss>")
    path.write_text("\n".join(out), encoding="utf-8")


SOURCE_ERRORS: list[str] = []


def describe(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        try:
            body = e.read(300).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            body = ""
        return f"HTTP {e.code} {e.reason} {e.url} {body}".strip()
    return f"{type(e).__name__}: {e}"


def attempt(name: str, fn, default):
    """Run one source; on failure keep going and surface the error in CI."""
    t0 = time.time()
    print(f"fetching {name}…", file=sys.stderr)
    try:
        out = fn()
        n = len(out.get("vulnerabilities", [])) if isinstance(out, dict) else len(out)
        print(f"  {name}: {n} records in {time.time() - t0:.0f}s", file=sys.stderr)
        return out
    except Exception as e:  # noqa: BLE001
        msg = f"{name} failed after {time.time() - t0:.0f}s: {describe(e)}"
        SOURCE_ERRORS.append(msg)
        # GitHub Actions turns this into an annotation on the run.
        print(f"::warning title=Source failed::{msg}", flush=True)
        return default


def live_sources() -> dict:
    kev = attempt("CISA KEV", fetch_kev, {})
    nvd = attempt("NVD critical", fetch_nvd_critical, [])
    ghsa = attempt("GitHub critical advisories", lambda: fetch_ghsa("reviewed", CRITICAL_DAYS, "critical"), [])
    malware = attempt("GitHub malware advisories", lambda: fetch_ghsa("malware", MALWARE_DAYS, None), [])
    print(f"checking downloads for {len(malware)} malware advisories…", file=sys.stderr)
    prefetch_npm_downloads([(v.get("package") or {}).get("name", "")
                            for a in malware for v in a.get("vulnerabilities") or []
                            if (v.get("package") or {}).get("ecosystem") == "npm"])
    return {"kev": kev, "nvd": nvd, "ghsa": ghsa, "malware": malware,
            "nvd_lookup": fetch_nvd_one, "epss": fetch_epss, "downloads": monthly_downloads}


def fixture_sources(d: Path) -> dict:
    j = lambda n, default: load_json(d / n, default)  # noqa: E731
    lookup = j("nvd_lookup.json", {})
    epss = j("epss.json", {})
    dls = j("downloads.json", {})
    return {"kev": j("kev.json", {}), "nvd": j("nvd.json", []), "ghsa": j("ghsa.json", []),
            "malware": j("malware.json", []),
            "nvd_lookup": lambda cid: lookup.get(cid),
            "epss": lambda cves: {c: epss[c] for c in cves if c in epss},
            "downloads": lambda eco, name: dls.get(f"{eco}:{name}")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="site", help="output directory")
    ap.add_argument("--fixtures", help="read upstream data from this directory instead of the network")
    ap.add_argument("--site-url", default=os.environ.get("SITE_URL", ""), help="public URL, used in the RSS feed")
    args = ap.parse_args()

    raw = fixture_sources(Path(args.fixtures)) if args.fixtures else live_sources()
    overrides = load_json(ROOT / "overrides.json", {})
    watchlist = load_json(ROOT / "watchlist.json", [])
    data = build(raw, overrides, watchlist)
    data["sourceErrors"] = SOURCE_ERRORS
    if not data["items"] and SOURCE_ERRORS:
        print("::error::every source failed; not deploying an empty site", flush=True)
        sys.exit(1)

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "web", out)
    (out / "data.json").write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    write_rss(data, out / "feed.xml", args.site_url)
    (out / ".nojekyll").write_text("")
    s = data["summary"]
    print(f"built {len(data['items'])} items · act {s['actNow']} · exploited7d {s['exploited7d']} "
          f"· watched {s['watched']} → {out}/", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # surface the traceback as a CI annotation, then fail
        import traceback
        tb = traceback.format_exc()
        print("::error title=Build crashed::" + tb.strip().replace("\n", "%0A"), flush=True)
        raise
