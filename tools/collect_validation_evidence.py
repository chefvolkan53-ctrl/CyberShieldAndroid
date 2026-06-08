#!/usr/bin/env python3
"""Collect CyberShield validation evidence.

The script gathers local build/model evidence and, when ADB is available,
captures basic device evidence. AMTSO URLs are safe feature-check pages; this
script can open them for manual observation, but it does not claim a pass unless
human/device evidence is reviewed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PACKAGE = "com.monster.cybershield"
AMTSO_ANDROID_PHISHING = "https://www.amtso.org/check-android-phishing-page"
AMTSO_ANDROID_MALWARE = "https://www.amtso.org/feature-settings-check-download-of-malware-for-android-based-solutions/"
AMTSO_ANDROID_DRIVE_BY = "https://www.amtso.org/feature-settings-check-drive-by-download-for-android-based-solutions/"


def run(cmd: list[str], cwd: Path, timeout: int = 60) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
        return {
            "cmd": cmd,
            "exit_code": proc.returncode,
            "duration_sec": round(time.time() - started, 3),
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as exc:
        return {
            "cmd": cmd,
            "exit_code": -1,
            "duration_sec": round(time.time() - started, 3),
            "stdout": "",
            "stderr": f"{exc.__class__.__name__}: {exc}",
        }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def adb_path(explicit: str | None) -> str | None:
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("adb")
    if found:
        return found
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
    if local.is_file():
        return str(local)
    return None


def collect_static(repo: Path, out: Path) -> dict:
    evidence: dict[str, object] = {}
    evidence["git_head"] = run(["git", "rev-parse", "HEAD"], repo, 10)
    evidence["git_status"] = run(["git", "status", "--short"], repo, 10)
    evidence["calibration_gate"] = run([sys.executable, "tools/validate_model_calibration.py", "--repo", "."], repo, 30)
    evidence["model_catalog_json"] = run([sys.executable, "-m", "json.tool", "app/src/main/assets/model_catalog.json"], repo, 30)
    evidence["threat_feed_probe"] = run([
        sys.executable,
        "tools/build_threat_intel_feed.py",
        "--output",
        str(out / "threat_intel_probe.json"),
        "--max-url-patterns",
        "200",
        "--max-domains",
        "200",
        "--max-cidrs",
        "200",
    ], repo, 90)

    manifest = repo / "app/src/main/AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8", errors="replace")
    evidence["manifest_static_checks"] = {
        "allow_backup_false": 'android:allowBackup="false"' in text,
        "cleartext_false": 'android:usesCleartextTraffic="false"' in text,
        "vpn_service_permission": "android.permission.BIND_VPN_SERVICE" in text,
        "diagnostic_activities_not_exported": all(
            f'android:name=".{name}"' in text and 'android:exported="false"' in text
            for name in ("SelfTestActivity", "AttackSimulationActivity", "SourceFieldTestActivity", "CalibrationActivity")
        ),
    }
    return evidence


def collect_adb(repo: Path, out: Path, adb: str, launch_amtso: bool) -> dict:
    evidence: dict[str, object] = {}
    evidence["devices"] = run([adb, "devices", "-l"], repo, 10)
    evidence["package_path"] = run([adb, "shell", "pm", "path", PACKAGE], repo, 10)
    evidence["package_dump"] = run([adb, "shell", "dumpsys", "package", PACKAGE], repo, 20)
    evidence["battery"] = run([adb, "shell", "dumpsys", "battery"], repo, 10)
    evidence["meminfo"] = run([adb, "shell", "dumpsys", "meminfo", PACKAGE], repo, 20)
    evidence["vpn_process"] = run([adb, "shell", "pidof", PACKAGE], repo, 10)

    if launch_amtso:
        evidence["amtso_phishing_launch"] = run([
            adb, "shell", "am", "start",
            "-n", f"{PACKAGE}/.LinkScanActivity",
            "-a", "android.intent.action.VIEW",
            "-d", AMTSO_ANDROID_PHISHING,
        ], repo, 15)
        time.sleep(3)
        phishing_png = out / "amtso_phishing_screen.png"
        with phishing_png.open("wb") as handle:
            proc = subprocess.run([adb, "exec-out", "screencap", "-p"], cwd=str(repo), stdout=handle, stderr=subprocess.PIPE)
        evidence["amtso_phishing_screenshot"] = {
            "path": str(phishing_png),
            "exit_code": proc.returncode,
            "stderr": proc.stderr.decode("utf-8", errors="replace"),
        }
        evidence["amtso_malware_page_launch"] = run([
            adb, "shell", "am", "start",
            "-a", "android.intent.action.VIEW",
            "-d", AMTSO_ANDROID_MALWARE,
        ], repo, 15)
        evidence["amtso_drive_by_page_launch"] = run([
            adb, "shell", "am", "start",
            "-a", "android.intent.action.VIEW",
            "-d", AMTSO_ANDROID_DRIVE_BY,
        ], repo, 15)
    return evidence


def write_markdown(out: Path, evidence: dict) -> None:
    static = evidence.get("static", {})
    adb = evidence.get("adb", {})
    cal = static.get("calibration_gate", {})
    feed = static.get("threat_feed_probe", {})
    checks = static.get("manifest_static_checks", {})
    lines = [
        "# CyberShield Validation Evidence",
        "",
        f"- Generated at: `{evidence['generated_at']}`",
        f"- Git HEAD: `{static.get('git_head', {}).get('stdout', '').strip()}`",
        f"- Calibration gate exit: `{cal.get('exit_code')}`",
        f"- Threat feed probe exit: `{feed.get('exit_code')}`",
        f"- ADB available: `{bool(adb)}`",
        "",
        "## Static Checks",
        "",
    ]
    for key, value in checks.items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend([
        "",
        "## AMTSO Status",
        "",
        "- AMTSO phishing/malware pages are safe feature checks, not live malware.",
        "- A launched page is not by itself a pass; pass/fail requires CyberShield notification/event evidence.",
        f"- Android phishing URL: {AMTSO_ANDROID_PHISHING}",
        f"- Android malware download URL: {AMTSO_ANDROID_MALWARE}",
        f"- Android drive-by URL: {AMTSO_ANDROID_DRIVE_BY}",
        "",
        "## Remaining External Evidence",
        "",
        "- 24-48 hour field monitoring CSV must be collected with `tools/android_field_monitor.py`.",
        "- Benign URL/SMS/APK false-positive corpus must be run and reviewed.",
        "- MASA/OWASP result requires an independent reviewer; this repo can only prepare evidence.",
    ])
    if adb:
        lines.extend([
            "",
            "## Device Evidence",
            "",
            f"- `adb devices` exit: `{adb.get('devices', {}).get('exit_code')}`",
            f"- package path exit: `{adb.get('package_path', {}).get('exit_code')}`",
            f"- meminfo exit: `{adb.get('meminfo', {}).get('exit_code')}`",
        ])
        shot = adb.get("amtso_phishing_screenshot", {})
        if shot:
            lines.append(f"- AMTSO phishing screenshot: `{shot.get('path')}`")
    (out / "VALIDATION_EVIDENCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out-dir", default="validation-evidence")
    parser.add_argument("--adb")
    parser.add_argument("--launch-amtso", action="store_true")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (repo / args.out_dir / stamp).resolve()
    out.mkdir(parents=True, exist_ok=True)

    evidence = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "static": collect_static(repo, out),
    }

    adb = adb_path(args.adb)
    if adb:
        evidence["adb"] = collect_adb(repo, out, adb, args.launch_amtso)

    write_json(out / "evidence.json", evidence)
    write_markdown(out, evidence)
    print(str(out))

    static = evidence["static"]
    failed = [
        name for name in ("calibration_gate", "model_catalog_json", "threat_feed_probe")
        if static.get(name, {}).get("exit_code") != 0
    ]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
