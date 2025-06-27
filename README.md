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
