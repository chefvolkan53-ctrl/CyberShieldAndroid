#!/usr/bin/env python3
import argparse
import csv
import io
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/dropv6.txt"
URLHAUS_LEGACY_TEXT_URL = "https://urlhaus.abuse.ch/downloads/text/"

TRUSTED_SHARED_HOST_SUFFIXES = (
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "youtu.be",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "samsung.com",
    "samsungapps.com",
    "whatsapp.com",
    "whatsapp.net",
    "facebook.com",
    "instagram.com",
)

DEFAULT_DOH_ENDPOINTS = [
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.nextdns.io",
    "dns.adguard-dns.com",
]

DEFAULT_RISKY_PORTS = [21, 22, 23, 25, 110, 135, 139, 143, 389, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]


def main():
    parser = argparse.ArgumentParser(description="Build CyberShield threat intelligence feed")
    parser.add_argument("--output", default="security-updates/threat_intel.json")
    parser.add_argument("--max-url-patterns", type=int, default=20000)
    parser.add_argument("--max-domains", type=int, default=12000)
    parser.add_argument("--max-cidrs", type=int, default=8000)
    args = parser.parse_args()

    feed = {
        "schema": 1,
        "id": "threat_intel",
        "version": datetime.now(timezone.utc).strftime("%Y.%m.%d.%H%M"),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "malicious_domains": [],
        "malicious_ips": [],
        "malicious_cidrs": [],
        "phishing_patterns": [],
        "doh_endpoints": DEFAULT_DOH_ENDPOINTS,
        "risky_ports": DEFAULT_RISKY_PORTS,
        "exploited_cves": [],
        "source_status": {},
    }

    domains = set()
    ips = set()
    cidrs = set()
    url_patterns = set()
    cves = set()

    collect_urlhaus(domains, ips, url_patterns, feed["source_status"])
    collect_phishtank(url_patterns, feed["source_status"])
    collect_spamhaus(cidrs, feed["source_status"])
    collect_cisa(cves, feed["source_status"])

    feed["malicious_domains"] = sorted(domains)[: args.max_domains]
    feed["malicious_ips"] = sorted(ips)[: args.max_domains]
    feed["malicious_cidrs"] = sorted(cidrs)[: args.max_cidrs]
    feed["phishing_patterns"] = sorted(url_patterns, key=lambda x: (len(x), x), reverse=True)[: args.max_url_patterns]
    feed["exploited_cves"] = sorted(cves, reverse=True)[:5000]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(feed, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")

    print(json.dumps({
        "output": args.output,
        "domains": len(feed["malicious_domains"]),
        "ips": len(feed["malicious_ips"]),
        "cidrs": len(feed["malicious_cidrs"]),
        "url_patterns": len(feed["phishing_patterns"]),
        "cves": len(feed["exploited_cves"]),
        "source_status": feed["source_status"],
    }, indent=2, sort_keys=True))


def collect_urlhaus(domains, ips, url_patterns, status):
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    urls = []
    if auth_key:
        export_url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{urllib.parse.quote(auth_key)}/recent.csv"
        try:
            text = fetch_text(export_url, timeout=35)
            urls.extend(urlhaus_urls_from_csv(text))
            status["urlhaus"] = "ok:authenticated_recent_csv"
        except Exception as exc:
            status["urlhaus"] = f"failed_authenticated:{short_error(exc)}"
    if not urls:
        try:
            text = fetch_text(URLHAUS_LEGACY_TEXT_URL, timeout=25)
            urls.extend(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))
            status["urlhaus"] = "ok:legacy_text"
        except Exception as exc:
            status["urlhaus"] = f"skipped:{short_error(exc)}"
    for url in urls:
        add_url_ioc(url, domains, ips, url_patterns)


def collect_phishtank(url_patterns, status):
    app_key = os.environ.get("PHISHTANK_APP_KEY", "").strip()
    if not app_key:
        status["phishtank"] = "skipped:no_secret"
        return
    url = f"http://data.phishtank.com/data/{urllib.parse.quote(app_key)}/online-valid.json"
    try:
        data = json.loads(fetch_text(url, timeout=35))
        for entry in data:
            value = str(entry.get("url", "")).strip().lower()
            if value.startswith(("http://", "https://")):
                url_patterns.add(value)
        status["phishtank"] = f"ok:{len(data)}"
    except Exception as exc:
        status["phishtank"] = f"skipped:{short_error(exc)}"


def collect_spamhaus(cidrs, status):
    count = 0
    errors = []
    for name, url in (("drop_v4", SPAMHAUS_DROP_URL), ("drop_v6", SPAMHAUS_DROP_V6_URL)):
        try:
            text = fetch_text(url, timeout=25)
            for line in text.splitlines():
                value = line.split(";", 1)[0].strip()
                if "/" not in value:
                    continue
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    cidrs.add(str(network))
                    count += 1
                except ValueError:
                    continue
        except Exception as exc:
            errors.append(f"{name}:{short_error(exc)}")
    status["spamhaus_drop"] = f"ok:{count}" if count else "skipped:" + ",".join(errors)


def collect_cisa(cves, status):
    try:
        data = json.loads(fetch_text(CISA_KEV_URL, timeout=30))
        for entry in data.get("vulnerabilities", []):
            cve = str(entry.get("cveID", "")).strip().upper()
            if cve.startswith("CVE-"):
                cves.add(cve)
        status["cisa_kev"] = f"ok:{len(cves)}"
    except Exception as exc:
        status["cisa_kev"] = f"skipped:{short_error(exc)}"


def urlhaus_urls_from_csv(text):
    cleaned = "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
    if not cleaned.strip():
        return []
    out = []
    reader = csv.DictReader(io.StringIO(cleaned))
    for row in reader:
        for key in ("url", "URL", "urlhaus_reference"):
            value = (row.get(key) or "").strip()
            if value.startswith(("http://", "https://")):
                out.append(value)
                break
    if out:
        return out
    reader = csv.reader(io.StringIO(cleaned))
    for row in reader:
        for value in row:
            value = value.strip()
            if value.startswith(("http://", "https://")):
                out.append(value)
                break
    return out


def add_url_ioc(url, domains, ips, url_patterns):
    value = url.strip().lower()
    if not value.startswith(("http://", "https://")):
        return
    url_patterns.add(value)
    host = urllib.parse.urlparse(value).hostname or ""
    host = host.lower().strip(".")
    if not host or is_trusted_shared_host(host):
        return
    try:
        ipaddress.ip_address(host)
        ips.add(host)
    except ValueError:
        domains.add(host[4:] if host.startswith("www.") else host)


def is_trusted_shared_host(host):
    return any(host == suffix or host.endswith("." + suffix) for suffix in TRUSTED_SHARED_HOST_SUFFIXES)


def fetch_text(url, timeout):
    request = urllib.request.Request(url, headers={
        "User-Agent": "CyberShieldAndroidThreatIntel/1.0 (+https://github.com/chefvolkan53-ctrl/CyberShieldAndroid)"
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(20 * 1024 * 1024)
        return data.decode("utf-8", errors="replace")


def short_error(exc):
    text = re.sub(r"\s+", " ", str(exc)).strip()
    return text[:120] if text else exc.__class__.__name__


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"fatal: {error}", file=sys.stderr)
        sys.exit(1)
