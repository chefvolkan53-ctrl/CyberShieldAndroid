# CyberShield LLM Cyber Analyst Training

This pipeline prepares a defensive cyber analyst LLM for CyberShield. The LLM is not the primary packet/APK detector. CyberShield's TFLite models still produce detection scores. The LLM explains the event, maps it to cyber knowledge, checks false-positive context, and recommends Android-safe intervention.

## Source Strategy

Local desktop folders are streamed into instruction examples:

- `sosyal mühendislik`
- `cybershield_tflite_policy`
- `Kötü Amaçlı Yazılım (Mirai)`
- `android malware`
- `attack`
- `iot attack`
- `Post-Kuantum`
- `network`
- `doh`
- `dns saldırı`
- `phising`
- `wifi`
- `Honeypots`
- `darknet`
- `gizlilik`
- `anomali`

External sources are downloaded as defensive standards, rules, metadata and threat-intelligence feeds:

- MITRE ATT&CK STIX
- MITRE D3FEND mappings
- CWE / CAPEC taxonomy archives
- NVD recent CVE API
- CISA KEV catalog
- URLhaus recent malware URL metadata
- MalwareBazaar recent metadata only
- PhishTank feed if an API key is configured
- Spamhaus DROP / EDROP
- SigmaHQ detection rules
- YARA rule repository metadata
- Emerging Threats Open Suricata rules
- NIST SP 800-61 incident handling
- OWASP MASVS / MASTG

The downloader does not fetch executable malware samples.

## Prepare Internet Sources

Run from the repository root:

```powershell
python tools\download_cybershield_llm_sources.py `
  --output-dir training\llm_external_sources `
  --nvd-days 7
```

Optional environment variables:

```powershell
$env:NVD_API_KEY="your-nvd-api-key"
$env:PHISHTANK_APP_KEY="your-phishtank-key"
$env:MALWAREBAZAAR_AUTH_KEY="your-malwarebazaar-key"
```

OpenPhish is not enabled by default because feed access and licensing can vary:

```powershell
python tools\download_cybershield_llm_sources.py `
  --output-dir training\llm_external_sources `
  --nvd-days 7 `
  --include-openphish
```

## Build The SFT Dataset

Small verification run:

```powershell
python tools\build_cybershield_llm_dataset.py `
  --desktop-root "C:\Users\Monster\Desktop" `
  --source-manifest training\llm_source_manifest.json `
  --external-root training\llm_external_sources `
  --output training\llm_data\cybershield_sft_dataset.jsonl `
  --summary training\llm_data\cybershield_sft_summary.json `
  --max-rows-per-file 5
```

Larger training run:

```powershell
python tools\build_cybershield_llm_dataset.py `
  --desktop-root "C:\Users\Monster\Desktop" `
  --source-manifest training\llm_source_manifest.json `
  --external-root training\llm_external_sources `
  --output training\llm_data\cybershield_sft_dataset.jsonl `
  --summary training\llm_data\cybershield_sft_summary.json `
  --max-rows-per-file 200
```

Full uncapped run:

```powershell
python tools\build_cybershield_llm_dataset.py `
  --desktop-root "C:\Users\Monster\Desktop" `
  --source-manifest training\llm_source_manifest.json `
  --external-root training\llm_external_sources `
  --output training\llm_data\cybershield_sft_dataset.jsonl `
  --summary training\llm_data\cybershield_sft_summary.json `
  --max-rows-per-file 0
```

The full run can be very large because several desktop CSVs are multi-GB. Use the capped run first.

## Colab Training

Upload `training\llm_data\cybershield_sft_dataset.jsonl` to:

```text
/content/drive/MyDrive/CyberShield/llm/cybershield_sft_dataset.jsonl
```

Open:

```text
training/colab/CyberShield_LLM_CyberAnalyst_QLoRA.ipynb
```

Default base model:

```text
Qwen/Qwen2.5-7B-Instruct
```

Recommended hardware:

- Colab Pro L4/A100 for 7B QLoRA.
- Smaller instruct model if free-tier GPU memory is insufficient.

Output:

```text
/content/drive/MyDrive/CyberShield/llm/cybershield-cyber-analyst-lora
```

## Intended Runtime Role

CyberShield should use this model as a policy and explanation layer:

1. TFLite models detect suspicious APK, DNS, DoH, network, Wi-Fi, phishing, social engineering or anomaly signals.
2. Policy engine decides whether the event can alert directly or only support another model.
3. LLM explains:
   - what happened,
   - why it is risky,
   - what evidence supports it,
   - what false-positive checks are required,
   - what Android-safe intervention can be offered.
4. User approves high-impact actions such as quarantine, uninstall intent, temporary block or allowlist.

## Safety Guardrails

The dataset uses a defensive system prompt. It should not train the model to produce exploit steps, malware code, credential theft, unauthorized intrusion or persistence instructions.

The assistant output is structured to include:

- `threat_category`
- `risk_level`
- `analyst_summary`
- `evidence`
- `recommended_action`
- `user_message`
- `false_positive_check`
- `android_limitations`
- `next_step`

## Honest Limitation

This pipeline prepares the dataset and Colab training path. Full LLM training still requires a GPU run in Colab or another training machine. A trained LoRA adapter should be evaluated before being used in production.
