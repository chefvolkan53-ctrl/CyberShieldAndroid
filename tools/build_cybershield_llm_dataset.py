#!/usr/bin/env python3
"""Build a defensive SFT dataset for the CyberShield cyber analyst LLM.

The builder streams local CSV/JSON/text sources and downloaded public
knowledge feeds into instruction examples. It keeps raw malware binaries out of
the dataset and focuses on defensive explanation, risk reasoning and Android
safe intervention guidance.
"""

from __future__ import annotations

import argparse
import bz2
import csv
import datetime as dt
import gzip
import json
import re
import tarfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MANIFEST = Path("training/llm_source_manifest.json")
DEFAULT_EXTERNAL_ROOT = Path("training/llm_external_sources")
DEFAULT_OUTPUT = Path("training/llm_data/cybershield_sft_dataset.jsonl")
DEFAULT_SUMMARY = Path("training/llm_data/cybershield_sft_summary.json")

TEXT_EXTENSIONS = {".txt", ".md", ".markdown", ".rst", ".log", ".rules", ".yml", ".yaml", ".xml"}
CSV_EXTENSIONS = {".csv", ".tsv"}
JSON_EXTENSIONS = {".json", ".jsonl", ".ndjson"}
SKIP_EXTENSIONS = {
    ".tflite",
    ".apk",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".pkl",
    ".pcap",
    ".pcapng",
    ".xlsx",
    ".xls",
    ".sql",
    ".xz",
    ".7z",
    ".rar",
    ".pdf",
}

SYSTEM_PROMPT = (
    "Sen CyberShield Android içinde çalışan savunma odaklı siber güvenlik analistisin. "
    "Sadece tespit, açıklama, risk gerekçesi, yanlış alarm kontrolü ve kullanıcı onaylı "
    "güvenli müdahale önerisi üret. Exploit yazma, zararlı kod üretme, yetkisiz saldırı "
    "adımı anlatma. Android sınırlarını açıkça belirt: root/MDM olmadan sessiz APK silme, "
    "router firewall kuralı yazma veya saldırgan cihazı ağdan atma yapılamaz."
)


FOLDER_PROFILES = [
    ("sosyal mühendislik", "social_engineering", "phishing_or_social_engineering"),
    ("phising", "social_engineering", "phishing_or_social_engineering"),
    ("android malware", "android_malware", "malicious_or_suspicious_apk"),
    ("kötü amaçlı yazılım", "android_malware", "malicious_or_suspicious_apk"),
    ("mirai", "iot_malware", "mirai_or_android_malware"),
    ("attack", "network_attack", "network_intrusion"),
    ("iot attack", "iot_attack", "iot_network_attack"),
    ("post-kuantum", "pqc_tls", "pqc_or_tls_anomaly"),
    ("network", "network_attack", "network_intrusion"),
    ("doh", "dns_doh", "doh_or_dns_tunnel_risk"),
    ("dns saldırı", "dns_doh", "dns_attack"),
    ("wifi", "wifi_threat", "wifi_mitm_or_evil_twin"),
    ("honeypots", "honeypot_intel", "global_threat_intel"),
    ("darknet", "network_attack", "darknet_or_anonymous_network_risk"),
    ("gizlilik", "privacy", "privacy_or_leakage_risk"),
    ("anomali", "contextual_anomaly", "behavioral_anomaly"),
    ("cybershield_tflite_policy", "policy_engine", "policy_decision_support"),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize(value: str) -> str:
    return value.casefold().replace("\\", "/")


def classify_path(path: Path) -> tuple[str, str]:
    text = normalize(str(path))
    for marker, domain, category in FOLDER_PROFILES:
        if normalize(marker) in text:
            return domain, category
    return "general_security", "security_observation"


def risk_from_values(domain: str, row: dict[str, Any] | None = None, text: str = "") -> str:
    lower = normalize(json.dumps(row, ensure_ascii=False) if row is not None else text)
    bad_markers = [
        "malicious",
        "phishing",
        "attack",
        "mirai",
        "ransom",
        "trojan",
        "botnet",
        "spoof",
        "deauth",
        "flood",
        "scan",
        "brute",
        "ddos",
        "dos",
        "cve",
        "kev",
        "malware",
    ]
    benign_markers = ["benign", "legitimate", "normal", "clean", "allow", "safe"]
    if any(marker in lower for marker in bad_markers):
        return "high"
    if any(marker in lower for marker in benign_markers):
        return "low"
    if domain in {"wifi_threat", "network_attack", "android_malware", "dns_doh", "iot_attack"}:
        return "medium"
    return "informational"


def action_for(domain: str, risk: str) -> str:
    if risk in {"low", "informational"}:
        return "Olayı kaydet, yanlış alarm kontrolü yap, kullanıcıya gereksiz alarm üretme."
    actions = {
        "social_engineering": "Linki açma, kaynağı engelle, kullanıcıya phishing uyarısı göster ve güvenli sayma seçeneği sun.",
        "android_malware": "APK kurulumunu durdurması için kullanıcıyı uyar, dosyayı karantina listesine al, hash ve izinleri kaydet.",
        "network_attack": "VPN politika motorunda şüpheli IP/domain/port akışını geçici engelle, olay detayını aç ve geri alma seçeneği sun.",
        "iot_attack": "IoT/Mirai benzeri akışı yüksek riskli işaretle, dış hedefi engelle, kullanıcıya ağ değiştirme veya VPN kilidi öner.",
        "dns_doh": "DNS leak/DoH tünel şüphesinde resolver kilidini etkin tut, bilinmeyen DoH endpointini engelle ve Private DNS durumunu kontrol ettir.",
        "wifi_threat": "Şüpheli Wi-Fi ağını işaretle, otomatik yeniden bağlanmayı kapatmayı öner, VPN kilidini zorunlu tut ve gateway MAC değişimini izle.",
        "pqc_tls": "TLS/PQC oturum anomalisini destek sinyali olarak kullan, yıkıcı müdahaleden önce domain itibarı ve sertifika sinyallerini doğrula.",
        "honeypot_intel": "Riskli port/IP sinyalini threat-intel desteği olarak skora ekle; tek başına ülke/ASN engellemesi yapma.",
        "privacy": "Veri sızıntısı riskini açıkla, izin ve ağ politikalarını sıkılaştır, kullanıcı onaylı engelleme uygula.",
        "contextual_anomaly": "Davranış anomalisini destek sinyali yap, doğrudan engelleme için ikinci kanıt iste.",
        "policy_engine": "Ana tespit modelinden gelen risk ve kullanıcı politikasına göre en az yıkıcı müdahaleyi seç.",
    }
    return actions.get(domain, "Kullanıcı onayıyla geçici engelleme uygula, olay geçmişine kanıtları yaz.")


def fp_check_for(domain: str) -> str:
    checks = {
        "social_engineering": "Google, Samsung, banka ve bilinen hizmet allowlist sinyallerini; kısa link redirect zincirini ve sayfa içeriğini kontrol et.",
        "android_malware": "APK imzası, Play Store kaynağı, bilinen temiz paket adı, izin yoğunluğu ve dex/string sinyallerini birlikte doğrula.",
        "network_attack": "CDN, WhatsApp/Gmail/YouTube gibi temiz yüksek hacimli trafik, video görüşme ve sistem güncelleme akışlarını allowlist ile ayır.",
        "dns_doh": "Seçili Cloudflare/Quad9 resolver, Android Private DNS ve sistem DNS davranışını normal kabul et; bilinmeyen DoH endpointlerinde alarm üret.",
        "wifi_threat": "SSID/BSSID değişimi, RSSI sıçraması ve gateway MAC değişimini tek başına değil birlikte değerlendir.",
        "pqc_tls": "TLS el sıkışması anomalilerini sertifika, SNI, domain itibarı ve tekrar eden başarısız oturumlarla birlikte değerlendir.",
    }
    return checks.get(domain, "Benign allowlist, kullanıcı bağlamı, tekrar sıklığı ve ikinci model kanıtı ile yanlış alarmı azalt.")


def android_limitations(domain: str) -> str:
    if domain == "android_malware":
        return "CyberShield root/MDM olmadan APK'yi sessizce silemez; kullanıcıyı kaldırma ekranına yönlendirir veya dosyayı kendi erişebildiği alanda karantinaya alır."
    if domain == "wifi_threat":
        return "Telefon saldırgan cihazı modemden atamaz; güvenli ağdan ayrılma, VPN kilidi ve kullanıcı uyarısı uygulayabilir."
    if domain in {"network_attack", "dns_doh", "iot_attack"}:
        return "Android VpnService ile akışları engelleyebilir; sistem dışı router/firewall kuralını kullanıcı onayı veya ayrı yönetim entegrasyonu olmadan yazamaz."
    return "Müdahale kullanıcı onaylı, geri alınabilir ve Android izin sınırlarına uygun olmalıdır."


def compact_row(row: dict[str, Any], max_fields: int = 18, max_value: int = 160) -> dict[str, str]:
    compact: dict[str, str] = {}
    for key, value in list(row.items())[:max_fields]:
        text = "" if value is None else str(value)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_value:
            text = text[: max_value - 3] + "..."
        compact[str(key)[:80]] = text
    return compact


def make_record(source: Path | str, domain: str, category: str, evidence: dict[str, Any], risk: str) -> dict[str, Any]:
    evidence_text = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    user = (
        "CyberShield bu güvenlik sinyalini analiz et.\n"
        f"Kaynak: {source}\n"
        f"Modül: {domain}\n"
        f"Sinyaller: {evidence_text}\n"
        "Yanıtı kısa ama profesyonel ver; risk gerekçesi, yanlış alarm kontrolü ve Android içinde uygulanabilir müdahaleyi belirt."
    )
    answer = {
        "threat_category": category,
        "risk_level": risk,
        "analyst_summary": f"Bu olay {category} kategorisinde {risk} riskli bir CyberShield sinyali olarak değerlendirilmelidir.",
        "evidence": evidence,
        "recommended_action": action_for(domain, risk),
        "user_message": human_message(category, risk),
        "false_positive_check": fp_check_for(domain),
        "android_limitations": android_limitations(domain),
        "next_step": "Olay detay ekranını aç, kanıtları kullanıcıya göster, yüksek riskte engelle/karantinaya al/kaldır aksiyonunu kullanıcı onayıyla uygula.",
    }
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(answer, ensure_ascii=False)},
        ],
        "metadata": {
            "source": str(source),
            "domain": domain,
            "category": category,
            "risk": risk,
            "generated_at": utc_now(),
        },
    }


def human_message(category: str, risk: str) -> str:
    if risk in {"low", "informational"}:
        return "Bu olay düşük riskli görünüyor. CyberShield olayı kaydetti ve doğrudan müdahale uygulamadı."
    if "phishing" in category:
        return "Phishing şüphesi algılandı. Linki açmayın; CyberShield kaynağı engelleyebilir ve olayı inceleyebilir."
    if "apk" in category or "malware" in category:
        return "Riskli APK veya zararlı yazılım sinyali algılandı. Kurulumu durdurmanız ve karantina/kaldırma adımını onaylamanız önerilir."
    if "wifi" in category:
        return "Şüpheli Wi-Fi/MITM sinyali algılandı. VPN kilidi açık kalmalı ve gerekirse bu ağdan ayrılmalısınız."
    return "Şüpheli güvenlik olayı algılandı. CyberShield kanıtları gösterip güvenli müdahale seçenekleri sunacak."


def open_text(path: Path):
    for encoding in ("utf-8-sig", "utf-8", "cp1254", "latin-1"):
        try:
            return path.open("r", encoding=encoding, errors="replace", newline="")
        except UnicodeError:
            continue
    return path.open("r", encoding="utf-8", errors="replace", newline="")


def iter_csv_records(path: Path, limit: int) -> Iterable[dict[str, Any]]:
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    with open_text(path) as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
            dialect.delimiter = delimiter
        reader = csv.DictReader(handle, dialect=dialect)
        for idx, row in enumerate(reader):
            if limit and idx >= limit:
                break
            yield compact_row(row)


def iter_json_records(path: Path, limit: int) -> Iterable[dict[str, Any]]:
    suffixes = [s.lower() for s in path.suffixes]
    opener = bz2.open if suffixes[-2:] == [".json", ".bz2"] else open
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:  # type: ignore[arg-type]
            for idx, line in enumerate(handle):
                if limit and idx >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    item = {"line": line[:600]}
                yield compact_row(flatten(item), max_fields=18)
        return

    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:  # type: ignore[arg-type]
        data = json.load(handle)
    if isinstance(data, dict):
        if "objects" in data and isinstance(data["objects"], list):
            for item in data["objects"][: limit or None]:
                if isinstance(item, dict):
                    yield compact_row(flatten(item), max_fields=20)
        elif "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            for item in data["vulnerabilities"][: limit or None]:
                yield compact_row(flatten(item), max_fields=20)
        elif "data" in data and isinstance(data["data"], list):
            for item in data["data"][: limit or None]:
                yield compact_row(flatten(item), max_fields=20)
        elif "vulnerabilities" in data.get("KnownExploitedVulnerabilityCatalog", {}):
            items = data["KnownExploitedVulnerabilityCatalog"]["vulnerabilities"]
            for item in items[: limit or None]:
                yield compact_row(flatten(item), max_fields=20)
        else:
            yield compact_row(flatten(data), max_fields=24)
    elif isinstance(data, list):
        for item in data[: limit or None]:
            yield compact_row(flatten(item), max_fields=20)


def flatten(obj: Any, prefix: str = "", out: dict[str, Any] | None = None) -> dict[str, Any]:
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                flatten(value, name, out)
            else:
                out[name] = value
    elif isinstance(obj, list):
        for idx, value in enumerate(obj[:6]):
            name = f"{prefix}[{idx}]"
            if isinstance(value, (dict, list)):
                flatten(value, name, out)
            else:
                out[name] = value
    else:
        out[prefix or "value"] = obj
    return out


def iter_text_records(path: Path, limit: int, chunk_chars: int) -> Iterable[dict[str, Any]]:
    with open_text(path) as handle:
        buffer = ""
        emitted = 0
        for line in handle:
            line = line.strip()
            if not line:
                continue
            if len(buffer) + len(line) + 1 > chunk_chars:
                yield {"excerpt": buffer[:chunk_chars], "file_name": path.name}
                emitted += 1
                if limit and emitted >= limit:
                    return
                buffer = ""
            buffer = f"{buffer}\n{line}".strip()
        if buffer and (not limit or emitted < limit):
            yield {"excerpt": buffer[:chunk_chars], "file_name": path.name}


def iter_archive_metadata(path: Path, limit: int) -> Iterable[dict[str, Any]]:
    suffix = "".join(s.lower() for s in path.suffixes[-2:])
    names: list[str] = []
    try:
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()[: limit or 50]
        elif suffix in {".tar.gz", ".tgz"}:
            with tarfile.open(path) as tf:
                names = [m.name for m in tf.getmembers()[: limit or 50]]
        elif path.suffix.lower() == ".gz":
            names = [path.stem]
    except Exception as exc:  # noqa: BLE001
        yield {"archive": path.name, "parse_error": f"{type(exc).__name__}: {exc}"}
        return
    for name in names[: limit or None]:
        yield {"archive": path.name, "contained_file": name}


def iter_path_records(path: Path, max_rows: int, chunk_chars: int) -> tuple[Iterable[dict[str, Any]], str]:
    lower_suffixes = [s.lower() for s in path.suffixes]
    if path.suffix.lower() in CSV_EXTENSIONS:
        return iter_csv_records(path, max_rows), "csv"
    if path.suffix.lower() in JSON_EXTENSIONS or lower_suffixes[-2:] == [".json", ".bz2"]:
        return iter_json_records(path, max_rows), "json"
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return iter_text_records(path, max_rows, chunk_chars), "text"
    if path.suffix.lower() == ".zip" or "".join(lower_suffixes[-2:]) in {".tar.gz", ".jsongz"}:
        return iter_archive_metadata(path, max_rows), "archive_metadata"
    return iter([{"file_name": path.name, "extension": path.suffix.lower(), "size_bytes": path.stat().st_size}]), "file_metadata"


def should_skip_file(path: Path, include_binary_metadata: bool) -> bool:
    final_suffix = path.suffix.lower()
    if final_suffix in CSV_EXTENSIONS or final_suffix in JSON_EXTENSIONS or final_suffix in TEXT_EXTENSIONS:
        return False
    suffixes = {s.lower() for s in path.suffixes}
    if suffixes & SKIP_EXTENSIONS and not include_binary_metadata:
        return True
    return False


def iter_local_files(desktop_root: Path, folders: list[str]) -> Iterable[Path]:
    for folder in folders:
        base = desktop_root / folder
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file():
                yield path


def iter_external_files(external_root: Path) -> Iterable[Path]:
    raw = external_root / "raw"
    if raw.exists():
        for path in raw.rglob("*"):
            if path.is_file():
                yield path


def write_records(args: argparse.Namespace) -> dict[str, Any]:
    manifest = json.loads(Path(args.source_manifest).read_text(encoding="utf-8"))
    desktop_root = Path(args.desktop_root)
    external_root = Path(args.external_root)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    counters: Counter[str] = Counter()
    file_counters: Counter[str] = Counter()
    skipped: list[dict[str, Any]] = []

    local_files = list(iter_local_files(desktop_root, manifest.get("local_desktop_folders", [])))
    external_files = list(iter_external_files(external_root))

    with output.open("w", encoding="utf-8") as handle:
        for source_group, files in (("local", local_files), ("external", external_files)):
            for path in files:
                if should_skip_file(path, args.include_binary_metadata):
                    skipped.append({"path": str(path), "reason": "binary_or_large_format_skipped"})
                    continue
                try:
                    records, parser_kind = iter_path_records(path, args.max_rows_per_file, args.chunk_chars)
                    domain, category = classify_path(path)
                    if source_group == "external":
                        domain, category = classify_external(path, domain, category)
                    emitted_for_file = 0
                    for row in records:
                        risk = risk_from_values(domain, row=row)
                        evidence = {
                            "source_group": source_group,
                            "parser": parser_kind,
                            "file": path.name,
                            "signals": row,
                        }
                        handle.write(json.dumps(make_record(path, domain, category, evidence, risk), ensure_ascii=False) + "\n")
                        counters[domain] += 1
                        file_counters[str(path)] += 1
                        emitted_for_file += 1
                    if emitted_for_file == 0:
                        skipped.append({"path": str(path), "reason": "no_records_emitted"})
                except Exception as exc:  # noqa: BLE001
                    skipped.append({"path": str(path), "reason": f"{type(exc).__name__}: {exc}"})

    return {
        "schema": 1,
        "generated_at": utc_now(),
        "output": str(output),
        "desktop_root": str(desktop_root),
        "external_root": str(external_root),
        "local_files_seen": len(local_files),
        "external_files_seen": len(external_files),
        "records_total": sum(counters.values()),
        "records_by_domain": dict(counters),
        "files_with_records": len(file_counters),
        "skipped_count": len(skipped),
        "skipped_sample": skipped[:100],
        "max_rows_per_file": args.max_rows_per_file,
        "note": "This dataset is defensive SFT material. It does not include executable malware samples.",
    }


def classify_external(path: Path, fallback_domain: str, fallback_category: str) -> tuple[str, str]:
    name = normalize(path.name)
    if "attack" in name or "d3fend" in name or "cwe" in name or "capec" in name:
        return "standard_knowledge", "ttp_or_defense_mapping"
    if "kev" in name or "nvd" in name:
        return "vulnerability_intel", "exploited_vulnerability"
    if "urlhaus" in name or "phishtank" in name or "openphish" in name:
        return "threat_intel", "malicious_url_or_phishing"
    if "malwarebazaar" in name:
        return "threat_intel", "malware_hash_metadata"
    if "spamhaus" in name or "drop" in name:
        return "threat_intel", "malicious_network_block"
    if "sigma" in name or "yara" in name or "emerging" in name:
        return "detection_as_code", "detection_rule_mapping"
    if "owasp" in name or "nist" in name:
        return "incident_response", "mobile_security_or_incident_playbook"
    return fallback_domain, fallback_category


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--desktop-root", default=str(Path.home() / "Desktop"))
    parser.add_argument("--source-manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--external-root", default=str(DEFAULT_EXTERNAL_ROOT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--summary", default=str(DEFAULT_SUMMARY))
    parser.add_argument("--max-rows-per-file", type=int, default=200, help="0 means no per-file cap.")
    parser.add_argument("--chunk-chars", type=int, default=1800)
    parser.add_argument("--include-binary-metadata", action="store_true")
    args = parser.parse_args()

    summary = write_records(args)
    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["records_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
