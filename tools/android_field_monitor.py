#!/usr/bin/env python3
"""Collect long-running Android field metrics through ADB."""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


PACKAGE = "com.monster.cybershield"


def find_adb(explicit: str | None) -> str:
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("adb")
    if found:
        return found
    local = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if local.is_file():
        return str(local)
    raise SystemExit("adb not found")


def shell(adb: str, command: str, timeout: int = 10) -> str:
    proc = subprocess.run([adb, "shell", command], text=True, capture_output=True, timeout=timeout)
    return proc.stdout + proc.stderr


def parse_battery(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_")
        out[key] = value.strip()
    return out


def parse_meminfo(text: str) -> dict:
    total = ""
    for line in text.splitlines():
        if "TOTAL PSS:" in line:
            total = re.sub(r"\s+", " ", line.strip())
            break
    return {"total_pss_line": total}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb")
    parser.add_argument("--duration-minutes", type=float, default=30)
    parser.add_argument("--interval-seconds", type=float, default=60)
    parser.add_argument("--out", default="validation-evidence/field_metrics.csv")
    args = parser.parse_args()

    adb = find_adb(args.adb)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + args.duration_minutes * 60

    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "timestamp",
            "battery_level",
            "battery_status",
            "battery_plugged",
            "pid",
            "total_pss_line",
        ])
        writer.writeheader()
        while time.time() < deadline:
            battery = parse_battery(shell(adb, "dumpsys battery"))
            pid = shell(adb, f"pidof {PACKAGE}").strip()
            mem = parse_meminfo(shell(adb, f"dumpsys meminfo {PACKAGE}", timeout=20))
            writer.writerow({
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "battery_level": battery.get("level", ""),
                "battery_status": battery.get("status", ""),
                "battery_plugged": battery.get("plugged", ""),
                "pid": pid,
                "total_pss_line": mem.get("total_pss_line", ""),
            })
            handle.flush()
            time.sleep(args.interval_seconds)
    print(str(out.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
