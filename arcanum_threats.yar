# 🔍 Arcanum Threat Hunting Rules

Welcome to the official threat-hunting YARA ruleset for **OpSecGTP** — designed for red and blue teams targeting Windows environments where stealthy payload delivery, token theft, and persistence are common.

---

## 📁 Project Overview

This repository includes:

- `arcanum_threats.yar`: A fully validated YARA rule set focused on:
  - PowerShell base64 droppers
  - `.lnk` stagers and shortcut abuse
  - JWT and localStorage token theft
  - Discord and Steam credential targeting
  - AppData and registry-based persistence

- `README.md`: Documentation and scan instructions
- 🛠️ (Optional) PowerShell scripts for recursive scanning and archiving matches

---

## 🔧 Usage

### 🔹 Prerequisites

- Install [YARA](https://github.com/VirusTotal/yara/releases) (v4.2+ recommended)

### 🔹 Scan a Directory

```powershell
yara64.exe -r arcanum_threats.yar C:\Windows\SystemTemp


---

A curated YARA rule set designed for offensive and defensive security professionals to detect encoded payloads, malicious persistence, and credential theft artifacts across Windows environments.

Included Rule Summaries:
Rule Name	Purpose
Temp_Encoded_Payload	Detects Base64-encoded PowerShell stagers, JWTs, and C2 IPs in temp
LNK_StageLauncher	Flags .lnk shortcut files that silently execute hidden script loaders
Token_Grab_CacheDump	Finds credential/token theft from browser cache, fetch abuse
Steam_Discord_Grabber	Identifies malware that targets Discord and Steam token paths
Persistence_Loader	Triggers on registry-run, AppData, and WScript-based persistence
Each rule has been validated using yara64.exe, follows YARA 4.2+ syntax standards, and is tuned for real-world incident response and red team post-exploitation detection.
