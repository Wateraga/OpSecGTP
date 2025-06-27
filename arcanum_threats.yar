rule Temp_Encoded_Payload
{
    meta:
        author = "Arcanum Cyber Bot"
        description = "Detects PowerShell + Base64 encoded or JWT payloads in temp files"
        last_updated = "2025-06-27"
        tags = "temp, base64, powershell, token"

    strings:
        $b64 = /FromBase64String/i
        $enc = /powershell.*-enc\s+[A-Za-z0-9\/\+=]{20,}/ nocase
        $jwt = /eyJ[a-zA-Z0-9_-]{20,}/
        $ipport = /[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{2,5}/

    condition:
        2 of them and filesize < 2MB
}


rule LNK_StageLauncher
{
    meta:
        author = "Arcanum Cyber Bot"
        description = "Detects .lnk shortcuts that launch hidden PowerShell or script loaders"
        last_updated = "2025-06-27"
        tags = "lnk, persistence, powershell"

    strings:
        $1 = /cmd\.exe\s+\/c\s+start\s+.*\.ps1/i
        $2 = /powershell\.exe\s+-WindowStyle\s+Hidden/i
        $3 = /%TEMP%\\.*\.bat/i

    condition:
        1 of them and filesize < 500KB
}


rule Token_Grab_CacheDump
{
    meta:
        author = "Arcanum Cyber Bot"
        description = "Detects scripts stealing session or bearer tokens from browser storage"
        last_updated = "2025-06-27"
        tags = "token, browser, jwt, fetch"

    strings:
        $1 = /eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/
        $2 = /localStorage\.getItem\(.*token/i
        $3 = /sessionStorage\.getItem\(.*token/i
        $4 = /fetch\s*\(\s*['"]https?:\/\/.*\/api\/.*["']/i

    condition:
        2 of them
}


rule Steam_Discord_Grabber
{
    meta:
        author = "Arcanum Cyber Bot"
        description = "Detects malware targeting Discord or Steam token harvesting paths"
        last_updated = "2025-06-27"
        tags = "discord, steam, tokenstealer"

    strings:
        $1 = "discord_token"
        $2 = "C:\\Users\\" nocase
        $3 = "AppData\\Roaming\\discord" nocase
        $4 = /discord[a-z]?\/Local Storage\/leveldb/i
        $5 = /steamapps[\/\\]common/i

    condition:
        2 of them
}


rule Persistence_Loader
{
    meta:
        author = "Arcanum Cyber Bot"
        description = "Detects persistence via registry Run keys or AppData loaders"
        last_updated = "2025-06-27"
        tags = "registry, startup, autorun, persistence"

    strings:
        $1 = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
        $2 = /AppData\\(Roaming|Local)\\[^\\]+\\[^\\]+\.exe/i
        $3 = "WScript.Shell"
        $4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    condition:
        2 of them
}



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
