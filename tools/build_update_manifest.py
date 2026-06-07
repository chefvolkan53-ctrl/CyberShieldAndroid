#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description="Build CyberShield update manifest")
    parser.add_argument("--feed", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--output", default="security-updates/model_update_manifest.json")
    args = parser.parse_args()

    with open(args.feed, "r", encoding="utf-8-sig") as handle:
        feed = json.load(handle)
    with open(args.signature, "r", encoding="utf-8-sig") as handle:
        signed = json.load(handle)

    feed_name = os.path.basename(args.feed)
    raw_base = f"https://raw.githubusercontent.com/{args.repo}/{args.branch}/security-updates"
    manifest = {
        "schema": 1,
        "version": feed.get("version", datetime.now(timezone.utc).strftime("%Y.%m.%d.%H%M")),
        "min_app_version_code": 1,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "feeds": [
            {
                "id": "threat_intel",
                "version": feed.get("version", "unknown"),
                "url": f"{raw_base}/{feed_name}",
                "sha256": signed["sha256"],
                "signature": signed["signature"],
            }
        ],
        "models": [],
        "metadata": [],
        "catalog": None,
        "thresholds": [],
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"output": args.output, "version": manifest["version"]}, indent=2))


if __name__ == "__main__":
    main()
