# KISA-IR-Toolkit (Windows Incident Response Quick Triage)

This repository contains a PowerShell script that collects **volatile evidence and key host artifacts** for Windows 10/11 and Server 2019/2022.

## Files
- `ir_quick_triage.ps1` — main triage script
- `examples/` — example command lines
- `LICENSE` — MIT

## Usage
Open **PowerShell as Administrator** and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\ir_quick_triage.ps1
# or choose output folder and skip zip:
.\ir_quick_triage.ps1 -OutDir C:\IR -NoZip
```

The script creates a timestamped folder under the `-OutDir` (default: `.\KISA-IR-Output`) and saves:
- Host context, patches, users/groups/sessions
- Networking (ipconfig/arp/route/netstat/Get-NetTCPConnection, DNS cache)
- Services/drivers/scheduled tasks
- Common persistence (Run keys, Startup folders, WMI Event Subscriptions, Winlogon, LSA)
- Processes (tasklist/WMIC/Get-Process)
- **Optional Sysinternals** outputs if tools are on PATH (`autorunsc`, `tcpview`, `handle`, `listdlls`, `sigcheck`, `psinfo`, `pslist`)
- Event logs (Security, System, Application, Sysmon if present) — both EVTX and last-7-days CSV
- File inventories & SHA-256 hashes for hot spots

## Ready-to-publish GitHub link
```
https://github.com/Soo-boon/Sooboon-IR-Script
```

---

© 2025 MIT License.
