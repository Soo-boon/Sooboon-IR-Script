<# 
KISA Windows Incident Response Quick Triage Script
Author: (your name)
Date: 2025-08-16

What it does
- Creates a timestamped folder under .\KISA-IR-Output\
- Collects volatile + key host artifacts with built-in Windows commands (no external deps)
- Tries to use Sysinternals tools (Autoruns, TCPView, Handle, Listdlls, Sigcheck) if present on PATH
- Exports focused Windows Event Logs (Security, System, Application, Microsoft-Windows-Sysmon/Operational if available)
- Compresses results to a ZIP

Tested on: Windows 10/11, Server 2019/2022 (PowerShell 5+)
#>

[CmdletBinding()]
param(
    [switch]$NoZip,
    [string]$OutDir = ".\KISA-IR-Output"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# --- helpers ---
function New-IRFolder {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $base = Join-Path -Path $OutDir -ChildPath $ts
    New-Item -ItemType Directory -Force -Path $base | Out-Null
    return $base
}

function Run-Cmd {
    param([string]$File, [string]$Args = "", [string]$OutFile)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $File
        $psi.Arguments = $Args
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit(120000) | Out-Null
        $o = $p.StandardOutput.ReadToEnd() + "`n`n=== STDERR ===`n" + $p.StandardError.ReadToEnd()
        $o | Out-File -FilePath $OutFile -Encoding UTF8
    } catch {
        "ERROR running $File $Args : $($_.Exception.Message)" | Out-File -FilePath $OutFile -Encoding UTF8
    }
}

function Try-Tool {
    param([string]$Name)
    $p = (Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if ($null -ne $p) { return $p }
    return $null
}

$root = New-IRFolder
"Output root: $root"

# --- basic host context ---
$sys = Join-Path $root "00_system"
New-Item -ItemType Directory -Force -Path $sys | Out-Null

Get-ComputerInfo | Out-File (Join-Path $sys "computerinfo.txt")
Get-CimInstance Win32_OperatingSystem | Format-List * | Out-File (Join-Path $sys "os.txt")
Get-CimInstance Win32_ComputerSystem | Format-List * | Out-File (Join-Path $sys "computer.txt")
Get-CimInstance Win32_BIOS | Format-List * | Out-File (Join-Path $sys "bios.txt")
Get-HotFix | Sort-Object InstalledOn -Descending | Out-File (Join-Path $sys "hotfixes.txt")

systeminfo | Out-File (Join-Path $sys "systeminfo.txt")
wmic qfe list full | Out-File (Join-Path $sys "qfe.txt")

# Users, groups, sessions
$acct = Join-Path $root "01_accounts"
New-Item -ItemType Directory -Force -Path $acct | Out-Null
net user             > (Join-Path $acct "net_user.txt")
net localgroup       > (Join-Path $acct "net_localgroup.txt")
net localgroup administrators > (Join-Path $acct "administrators.txt")
qwinsta | Out-File (Join-Path $acct "sessions_qwinsta.txt")

# Networking
$netdir = Join-Path $root "02_network"
New-Item -ItemType Directory -Force -Path $netdir | Out-Null
ipconfig /all        > (Join-Path $netdir "ipconfig_all.txt")
arp -a               > (Join-Path $netdir "arp.txt")
route print          > (Join-Path $netdir "route.txt")
netstat -abno        > (Join-Path $netdir "netstat_abno.txt")
Get-DnsClientCache | Format-Table * -AutoSize | Out-File (Join-Path $netdir "dns_cache.txt")
Get-NetTCPConnection | Sort-Object State,LocalPort | Out-File (Join-Path $netdir "Get-NetTCPConnection.txt")

# Services, drivers, tasks
$svc = Join-Path $root "03_services_tasks"
New-Item -ItemType Directory -Force -Path $svc | Out-Null
sc query type= service state= all | Out-File (Join-Path $svc "services.txt")
Get-Service | Sort-Object Status,DisplayName | Out-File (Join-Path $svc "services_powershell.txt")
driverquery /v /fo list | Out-File (Join-Path $svc "drivers.txt")
wevtutil el | Out-File (Join-Path $svc "eventlogs_list.txt")
schtasks /query /fo LIST /v | Out-File (Join-Path $svc "scheduled_tasks.txt")

# Persistence: Run keys, Startup folders, WMI, Winlogon, LSA
$pers = Join-Path $root "04_persistence"
New-Item -ItemType Directory -Force -Path $pers | Out-Null

$runKeys = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($rk in $runKeys) { 
  try { Get-ItemProperty -Path $rk | Out-File (Join-Path $pers ("reg_" + ($rk -replace "[:\\]","_") + ".txt")) } catch {} 
}
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | 
    Out-File (Join-Path $pers "startup_programdata.txt")
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | 
    Out-File (Join-Path $pers "startup_appdata.txt")

# WMI Event Subscriptions (common persistence)
Get-WmiObject -Namespace root\subscription -Class __EventFilter        -ErrorAction SilentlyContinue | Out-File (Join-Path $pers "wmi_event_filters.txt")
Get-WmiObject -Namespace root\subscription -Class __EventConsumer      -ErrorAction SilentlyContinue | Out-File (Join-Path $pers "wmi_event_consumers.txt")
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Out-File (Join-Path $pers "wmi_bindings.txt")

# Winlogon & LSA keys
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > (Join-Path $pers "winlogon.txt")
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /s > (Join-Path $pers "lsa.txt")

# Processes
$proc = Join-Path $root "05_processes"
New-Item -ItemType Directory -Force -Path $proc | Out-Null
Get-Process | Sort-Object ProcessName | Out-File (Join-Path $proc "Get-Process.txt")
tasklist /v /fo list | Out-File (Join-Path $proc "tasklist_verbose.txt")
wmic process list full | Out-File (Join-Path $proc "wmic_process_full.txt")

# Sysinternals optional tools
$sysint = Join-Path $root "06_sysinternals_optional"
New-Item -ItemType Directory -Force -Path $sysint | Out-Null
$tools = @("autorunsc.exe","tcpview.exe","handle.exe","listdlls.exe","sigcheck.exe","psinfo.exe","pslist.exe")
foreach ($t in $tools) {
  $path = Try-Tool $t
  if ($path) {
    Run-Cmd -File $path -Args "/accepteula -a" -OutFile (Join-Path $sysint ($t + ".txt"))
  }
}

# Event logs (evtx + CSV extracts)
$ev = Join-Path $root "07_eventlogs"
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$channels = @(
 "Security","System","Application",
 "Microsoft-Windows-Sysmon/Operational"
)
foreach ($c in $channels) {
  try {
    wevtutil epl "$c" (Join-Path $ev ($c -replace "[\\/]", "_") + ".evtx")
    # Focused CSV (last 7 days)
    $q = @"
<QueryList><Query Id='0' Path='{0}'>
  <Select Path='{0}'>*[System[TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
</Query></QueryList>
"@ -f $c
    wevtutil qe "$c" /f:csv /q:"$q" > (Join-Path $ev ($c -replace "[\\/]", "_") + "_7d.csv")
  } catch { }
}

# Filesystem quick hits
$fs = Join-Path $root "08_filesystem"
New-Item -ItemType Directory -Force -Path $fs | Out-Null
Get-ChildItem "$env:ProgramData" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTime,LastWriteTime |
    Out-File (Join-Path $fs "programdata_inventory.txt")
Get-ChildItem "$env:APPDATA" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTime,LastWriteTime |
    Out-File (Join-Path $fs "appdata_inventory.txt")
Get-ChildItem "$env:SystemRoot\Temp","$env:TEMP" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName,Length,CreationTime,LastWriteTime | Out-File (Join-Path $fs "temp_inventory.txt")

# Installed software
$soft = Join-Path $root "09_software"
New-Item -ItemType Directory -Force -Path $soft | Out-Null
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
  Sort-Object DisplayName | Out-File (Join-Path $soft "installed_software_hklm.txt")
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
  Sort-Object DisplayName | Out-File (Join-Path $soft "installed_software_hkcu.txt")

# Hash hot spots (Downloads, Startup, Public Desktop)
$hash = Join-Path $root "10_hashes"
New-Item -ItemType Directory -Force -Path $hash | Out-Null
$targets = @(
  "$env:USERPROFILE\Downloads",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:PUBLIC\Desktop"
) | Where-Object { Test-Path $_ }
foreach ($t in $targets) {
  Get-ChildItem $t -File -Recurse -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | 
    Export-Csv -NoTypeInformation -Path (Join-Path $hash (($(Split-Path $t -Leaf) + "_sha256.csv")))
}

# Zip
if (-not $NoZip) {
  $zip = Join-Path $OutDir ("KISA-IR-" + (Split-Path $root -Leaf) + ".zip")
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($root, $zip)
  "ZIPPED: $zip" | Tee-Object -FilePath (Join-Path $root "zip_path.txt")
} else {
  "Skipped zip as requested." | Out-File (Join-Path $root "zip_skipped.txt")
}

Write-Host "Done. Output: $root"
