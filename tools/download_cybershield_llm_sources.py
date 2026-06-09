#!/usr/bin/env python3
"""Download public defensive knowledge sources for the CyberShield LLM pipeline.

The downloader intentionally fetches metadata, standards, rules and threat
intelligence feeds. It does not download executable malware samples.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_MANIFEST = Path("training/llm_source_manifest.json")
DEFAULT_OUTPUT = Path("training/llm_external_sources")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def suffix_for_url(url: str) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    for suffix in (".json", ".json.bz2", ".xml.zip", ".xml", ".zip", ".tar.gz", ".tgz", ".csv", ".txt", ".pdf"):
        if path.endswith(suffix):
            return suffix
    if "csv" in path:
        return ".csv"
    return ".bin"


def fetch_url(url: str, out: Path, timeout: int) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CyberShield-LLM-Source-Downloader/1.0",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    return {
        "bytes": out.stat().st_size,
        "sha256": sha256(out),
    }


def post_form(url: str, data: dict[str, str], out: Path, timeout: int) -> dict:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={
            "User-Agent": "CyberShield-LLM-Source-Downloader/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        payload = response.read()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)
    return {
        "bytes": out.stat().st_size,
        "sha256": sha256(out),
    }


def download_standard_sources(manifest: dict, raw_dir: Path, timeout: int) -> list[dict]:
    results: list[dict] = []
    for source in manifest.get("internet_sources", []):
        source_id = source["id"]
        url = source["url"]
        out = raw_dir / f"{source_id}{suffix_for_url(url)}"
        item = {
            "id": source_id,
            "kind": source.get("kind", ""),
            "url": url,
            "path": str(out),
            "downloaded_at": utc_now(),
        }
        try:
            item.update(fetch_url(url, out, timeout))
            item["status"] = "ok"
        except Exception as exc:  # noqa: BLE001 - result manifest should record all failures
            item["status"] = "error"
            item["error"] = f"{type(exc).__name__}: {exc}"
        results.append(item)
    return results


def download_optional_sources(raw_dir: Path, timeout: int, nvd_days: int, include_openphish: bool) -> list[dict]:
    results: list[dict] = []

    phishtank_key = os.environ.get("PHISHTANK_APP_KEY", "").strip()
    if phishtank_key:
        url = f"http://data.phishtank.com/data/{urllib.parse.quote(phishtank_key)}/online-valid.json.bz2"
        out = raw_dir / "phishtank_online_valid.json.bz2"
        item = {"id": "phishtank_online_valid", "url": url, "path": str(out), "downloaded_at": utc_now()}
        try:
            item.update(fetch_url(url, out, timeout))
            item["status"] = "ok"
        except Exception as exc:  # noqa: BLE001
            item["status"] = "error"
            item["error"] = f"{type(exc).__name__}: {exc}"
        results.append(item)
    else:
        results.append({"id": "phishtank_online_valid", "status": "skipped:no_PHISHTANK_APP_KEY"})

    mb_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
    mb_out = raw_dir / "malwarebazaar_recent_metadata.json"
    if mb_key:
        mb_item = {
            "id": "malwarebazaar_recent_metadata",
            "url": "https://mb-api.abuse.ch/api/v1/",
            "path": str(mb_out),
            "downloaded_at": utc_now(),
        }
        try:
            mb_item.update(post_form(mb_item["url"], {"query": "get_recent", "selector": "100", "auth_key": mb_key}, mb_out, timeout))
            mb_item["status"] = "ok"
        except Exception as exc:  # noqa: BLE001
            mb_item["status"] = "error"
            mb_item["error"] = f"{type(exc).__name__}: {exc}"
        results.append(mb_item)
    else:
        results.append({"id": "malwarebazaar_recent_metadata", "status": "skipped:no_MALWAREBAZAAR_AUTH_KEY"})

    if nvd_days > 0:
        end = dt.datetime.now(dt.timezone.utc)
        start = end - dt.timedelta(days=nvd_days)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }
        nvd_key = os.environ.get("NVD_API_KEY", "").strip()
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
        out = raw_dir / f"nvd_recent_{nvd_days}d.json"
        item = {"id": "nvd_recent_cves", "url": url, "path": str(out), "downloaded_at": utc_now()}
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "CyberShield-LLM-Source-Downloader/1.0",
                    **({"apiKey": nvd_key} if nvd_key else {}),
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(response.read())
            item.update({"bytes": out.stat().st_size, "sha256": sha256(out), "status": "ok"})
        except Exception as exc:  # noqa: BLE001
            item["status"] = "error"
            item["error"] = f"{type(exc).__name__}: {exc}"
        results.append(item)

    if include_openphish:
        url = "https://openphish.com/feed.txt"
        out = raw_dir / "openphish_feed.txt"
        item = {"id": "openphish_feed", "url": url, "path": str(out), "downloaded_at": utc_now()}
        try:
            item.update(fetch_url(url, out, timeout))
            item["status"] = "ok"
        except Exception as exc:  # noqa: BLE001
            item["status"] = "error"
            item["error"] = f"{type(exc).__name__}: {exc}"
        results.append(item)

    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--nvd-days", type=int, default=7)
    parser.add_argument("--include-openphish", action="store_true")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    output_dir = Path(args.output_dir)
    raw_dir = output_dir / "raw"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    results = []
    results.extend(download_standard_sources(manifest, raw_dir, args.timeout))
    results.extend(download_optional_sources(raw_dir, args.timeout, args.nvd_days, args.include_openphish))

    output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 1,
        "generated_at": utc_now(),
        "source_manifest": str(manifest_path),
        "results": results,
    }
    (output_dir / "download_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    ok = sum(1 for item in results if item.get("status") == "ok")
    skipped = sum(1 for item in results if str(item.get("status", "")).startswith("skipped"))
    errors = len(results) - ok - skipped
    print(json.dumps({"ok": ok, "skipped": skipped, "errors": errors, "report": str(output_dir / "download_report.json")}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
