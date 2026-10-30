#Requires -RunAsAdministrator

<#
.SYNOPSIS
    All-in-one OpenSSH Server setup for CTF remote access.
.DESCRIPTION
    1. Installs OpenSSH Server (if missing)
    2. Writes a clean sshd_config (Port 22, PasswordAuthentication yes)
    3. Finds the Administrator account (SID -500, works if renamed) or falls back to current user
    4. Enables it and sets password to root@2027
    5. Opens TCP 22 on Domain / Private / Public firewall profiles
    6. Restarts sshd
    7. VERIFIES: service running, port 22 listening, firewall rule active, localhost SSH test
    8. Detects public + local IP and prints the exact `ssh user@ip` command
#>

$ErrorActionPreference = 'Stop'
$NewPassword = 'root@2027'
$SshPort     = 22

function Write-Step($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [+] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Err2($m) { Write-Host "    [x] $m" -ForegroundColor Red }

# ---------------------------------------------------------------
# 1. Install OpenSSH Server
# ---------------------------------------------------------------
Write-Step "Installing OpenSSH Server"
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    Write-Ok "Installed."
} else {
    Write-Ok "Already installed."
}

# ---------------------------------------------------------------
# 2. Write a clean sshd_config (avoid trailing Match-block issues)
# ---------------------------------------------------------------
Write-Step "Writing sshd_config"
$sshdCfg = "$env:ProgramData\ssh\sshd_config"
if (-not (Test-Path $sshdCfg)) { New-Item -Path $sshdCfg -ItemType File -Force | Out-Null }

$cfg = Get-Content $sshdCfg -ErrorAction SilentlyContinue
# Drop any lines that set the options we override (commented or active)
$cfg = $cfg | Where-Object { $_ -notmatch '^\s*#?\s*(PasswordAuthentication|PermitRootLogin|Port\s+|PubkeyAuthentication|UseDNS|PermitEmptyPasswords)\b' }

# Insert our block BEFORE the first `Match` line (if any), else at the end
$ourBlock = @(
    "",
    "# ---- CTF setup ----",
    "Port $SshPort",
    "PasswordAuthentication yes",
    "PermitEmptyPasswords no",
    "PubkeyAuthentication yes",
    "UseDNS no",
    "PermitRootLogin yes"
)

$matchIdx = -1
for ($i = 0; $i -lt $cfg.Count; $i++) {
    if ($cfg[$i] -match '^\s*Match\s') { $matchIdx = $i; break }
}

if ($matchIdx -ge 0) {
    $new = @()
    $new += $cfg[0..($matchIdx-1)]
    $new += $ourBlock
    if ($matchIdx -lt $cfg.Count) { $new += $cfg[$matchIdx..($cfg.Count-1)] }
    $new | Set-Content -Path $sshdCfg -Encoding Ascii
    Write-Ok "Inserted config before Match block."
} else {
    $cfg + $ourBlock | Set-Content -Path $sshdCfg -Encoding Ascii
    Write-Ok "Appended config."
}

# Validate config with sshd -t if available
$sshdExe = "$env:WINDIR\System32\OpenSSH\sshd.exe"
if (Test-Path $sshdExe) {
    $test = & $sshdExe -t 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err2 "sshd config test FAILED: $test"
        throw "Fix sshd_config and re-run."
    } else {
        Write-Ok "sshd_config syntax OK."
    }
}

# ---------------------------------------------------------------
# 3. Locate Administrator account (SID -500), fall back to current user
# ---------------------------------------------------------------
Write-Step "Locating administrator account"
$admin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
if (-not $admin) {
    $admin = Get-LocalUser | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
}
if (-not $admin) {
    $admin = Get-LocalUser | Where-Object { $_.Name -ieq $env:USERNAME } | Select-Object -First 1
}
if (-not $admin) {
    throw "No usable local account found. Aborting."
}
$AdminUser = $admin.Name
Write-Ok "Using account: $AdminUser  (SID $($admin.SID.Value))"

# ---------------------------------------------------------------
# 4. Enable account + set password
# ---------------------------------------------------------------
Write-Step "Setting password on $AdminUser"
if (-not $admin.Enabled) {
    Enable-LocalUser -Name $AdminUser
    Write-Ok "Account enabled."
}
$secPwd = ConvertTo-SecureString $NewPassword -AsPlainText -Force
Set-LocalUser -Name $AdminUser -Password $secPwd -PasswordNeverExpires $true

try {
    $grp = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
           Where-Object { $_.Name -match "\\$([regex]::Escape($AdminUser))$" }
    if (-not $grp) {
        Add-LocalGroupMember -Group 'Administrators' -Member $AdminUser -ErrorAction Stop
        Write-Ok "Added to Administrators group."
    } else {
        Write-Ok "Already in Administrators group."
    }
} catch {
    Write-Warn "Could not verify Administrators membership: $($_.Exception.Message)"
}
Write-Ok "Password set to $NewPassword."

# ---------------------------------------------------------------
# 5. Firewall: TCP 22 on all profiles
# ---------------------------------------------------------------
Write-Step "Configuring firewall for TCP $SshPort"
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
    -DisplayName "OpenSSH Server (TCP $SshPort) - All Profiles" `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow `
    -LocalPort $SshPort -Profile Domain,Private,Public | Out-Null
Write-Ok "Rule created (Domain, Private, Public)."

# ---------------------------------------------------------------
# 6. Start + restart sshd
# ---------------------------------------------------------------
Write-Step "Starting sshd"
Set-Service -Name sshd -StartupType Automatic
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Service -Name sshd
Start-Sleep -Seconds 2
Write-Ok "sshd started."

# ---------------------------------------------------------------
# 7. VERIFY
# ---------------------------------------------------------------
Write-Step "Verifying setup"

$svc = Get-Service sshd
if ($svc.Status -eq 'Running') { Write-Ok "Service: RUNNING" } else { Write-Err2 "Service: $($svc.Status)" }

$listen = Get-NetTCPConnection -LocalPort $SshPort -State Listen -ErrorAction SilentlyContinue
if ($listen) {
    Write-Ok "Port $SshPort : LISTENING on $($listen.LocalAddress -join ', ')"
} else {
    Write-Err2 "Port $SshPort : NOT listening"
}

$rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if ($rule -and $rule.Enabled -eq 'True') { Write-Ok "Firewall rule: ENABLED ($($rule.Profile))" }
else { Write-Err2 "Firewall rule: missing or disabled" }

$t = Test-NetConnection -ComputerName '127.0.0.1' -Port $SshPort -WarningAction SilentlyContinue
if ($t.TcpTestSucceeded) { Write-Ok "Local SSH test (127.0.0.1:$SshPort): OK" }
else { Write-Err2 "Local SSH test: FAILED" }

# ---------------------------------------------------------------
# 8. Detect IPs (auto)
# ---------------------------------------------------------------
Write-Step "Detecting IP addresses"
$PublicIp = $null
try { $PublicIp = (& curl.exe -s --max-time 8 ifconfig.me).Trim() } catch {}
if (-not $PublicIp -or $PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    try { $PublicIp = (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { $PublicIp = '<UNKNOWN>' }
}

$LocalIp = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notmatch '^127\.' -and
        $_.IPAddress -notmatch '^169\.254\.' -and
        $_.IPAddress -ne '0.0.0.0' -and
        $_.AddressState -eq 'Preferred'
    } | Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress

Write-Ok "Public IP : $PublicIp"
Write-Ok "Local  IP : $LocalIp"

# ---------------------------------------------------------------
# 9. FINAL OUTPUT — exact ssh command
# ---------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH READY" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Username : $AdminUser"
Write-Host "  Password : $NewPassword"
Write-Host "  Port     : $SshPort"
Write-Host ""
Write-Host "  Connect from another PC over the internet:" -ForegroundColor Cyan
Write-Host "      ssh $AdminUser@$PublicIp" -ForegroundColor White
Write-Host ""
Write-Host "  Connect from the same LAN:" -ForegroundColor Cyan
Write-Host "      ssh $AdminUser@$LocalIp" -ForegroundColor White
Write-Host ""
if ($PublicIp -eq '<UNKNOWN>') {
    Write-Warn "Could not detect public IP. Check internet connectivity."
}
Write-Host "  Reminder: if the external connect times out, the router in" -ForegroundColor DarkYellow
Write-Host "  front of this PC still needs TCP $SshPort forwarded to $LocalIp." -ForegroundColor DarkYellow
Write-Host "================================================================" -ForegroundColor Green