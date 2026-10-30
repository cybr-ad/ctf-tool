#Requires -RunAsAdministrator
<#
.SYNOPSIS
    All-in-one SSH server setup for CTF remote access.
.DESCRIPTION
    - Installs OpenSSH Server
    - Configures sshd_config (Port 22, PasswordAuthentication yes)
    - Resolves user dynamically: SID -500 -> "Administrator" -> $env:USERNAME
    - Handles domain-joined hosts (no password reset for domain accounts)
    - Opens firewall TCP/22 on Domain, Private, Public
    - Detects local IP via default-route lookup (ignores Hyper-V/WSL/VPN)
    - Detects public IP live
    - Verifies service + port + firewall + localhost SSH
    - Prints exact `ssh user@ip` command
.PARAMETER UserMode
    Auto (default) | BuiltinAdmin | CurrentUser
#>
param(
    [ValidateSet('Auto','BuiltinAdmin','CurrentUser')]
    [string]$UserMode = 'Auto'
)

$ErrorActionPreference = 'Stop'
$NewPassword = 'root@2027'
$SshPort     = 22

function Step($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "    [x] $m" -ForegroundColor Red }

# --- Domain detection ---------------------------------------------------
$isDomain = $false
try { $isDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch {}

# --- 1. Install OpenSSH Server -----------------------------------------
Step "Installing OpenSSH Server"
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    Ok "Installed."
} else { Ok "Already installed." }

# --- 2. sshd_config ----------------------------------------------------
Step "Writing sshd_config"
$sshdCfg = "$env:ProgramData\ssh\sshd_config"
if (-not (Test-Path $sshdCfg)) { New-Item -Path $sshdCfg -ItemType File -Force | Out-Null }

$cfg = Get-Content $sshdCfg -ErrorAction SilentlyContinue
$cfg = $cfg | Where-Object { $_ -notmatch '^\s*#?\s*(PasswordAuthentication|PermitRootLogin|Port\s+|PubkeyAuthentication|UseDNS|PermitEmptyPasswords)\b' }

$block = @(
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
for ($i = 0; $i -lt $cfg.Count; $i++) { if ($cfg[$i] -match '^\s*Match\s') { $matchIdx = $i; break } }

if ($matchIdx -ge 0) {
    $new = @()
    $new += $cfg[0..($matchIdx-1)]
    $new += $block
    if ($matchIdx -lt $cfg.Count) { $new += $cfg[$matchIdx..($cfg.Count-1)] }
    $new | Set-Content -Path $sshdCfg -Encoding Ascii
    Ok "Inserted before Match block."
} else {
    $cfg + $block | Set-Content -Path $sshdCfg -Encoding Ascii
    Ok "Appended config."
}

$sshdExe = "$env:WINDIR\System32\OpenSSH\sshd.exe"
if (Test-Path $sshdExe) {
    $t = & $sshdExe -t 2>&1
    if ($LASTEXITCODE -ne 0) { Bad "sshd -t FAILED: $t"; throw "Fix sshd_config" } else { Ok "sshd_config valid." }
}

# --- 3. Resolve user ---------------------------------------------------
Step "Resolving SSH user (mode: $UserMode)"
$user = $null
$userSource = $null

if ($UserMode -eq 'CurrentUser') {
    $user = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
    if ($user) { $userSource = 'CurrentUser (local)' }
    else {
        $user = [pscustomobject]@{ Name = $env:USERNAME; SID = [pscustomobject]@{ Value = 'DOMAIN' }; Enabled = $true }
        $userSource = 'CurrentUser (domain)'
    }
}
else {
    # RID 500 (rename-safe)
    $user = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($user) { $userSource = 'BuiltinAdmin (SID -500)' }
    else {
        $user = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
        if ($user) { $userSource = 'BuiltinAdmin (name)' }
    }
    if (-not $user -and $UserMode -eq 'Auto') {
        $user = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
        if ($user) { $userSource = 'Fallback: current user (local)' }
        else {
            $user = [pscustomobject]@{ Name = $env:USERNAME; SID = [pscustomobject]@{ Value = 'DOMAIN' }; Enabled = $true }
            $userSource = 'Fallback: current user (domain)'
        }
    }
}

if (-not $user) { throw "No usable user found." }
$AdminUser = $user.Name
Ok "User: $AdminUser  (source: $userSource)"

# --- 4. Set password (skip for domain accounts) ------------------------
Step "Configuring password"
$isDomainAccount = ($userSource -like '*domain*') -or (-not (Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue))

if ($isDomainAccount) {
    Warn "Domain/AD account — not setting local password. Use your domain password to SSH."
} else {
    if (-not $user.Enabled) { Enable-LocalUser -Name $AdminUser; Ok "Account enabled." }
    $sec = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    Set-LocalUser -Name $AdminUser -Password $sec -PasswordNeverExpires $true
    Ok "Password set to $NewPassword."
    # Ensure Administrators membership
    try {
        $inGrp = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
                 Where-Object { $_.Name -match "\\$([regex]::Escape($AdminUser))$" }
        if (-not $inGrp) { Add-LocalGroupMember -Group 'Administrators' -Member $AdminUser -ErrorAction Stop; Ok "Added to Administrators." }
        else { Ok "Already in Administrators." }
    } catch { Warn "Could not verify Administrators: $($_.Exception.Message)" }
}

# --- 5. Firewall -------------------------------------------------------
Step "Configuring firewall TCP/$SshPort"
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
    -DisplayName "OpenSSH Server (TCP $SshPort) - All Profiles" `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow `
    -LocalPort $SshPort -Profile Domain,Private,Public | Out-Null
Ok "Rule created (Domain, Private, Public)."

# --- 6. Start sshd -----------------------------------------------------
Step "Starting sshd"
Set-Service -Name sshd -StartupType Automatic
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Service -Name sshd
Start-Sleep -Seconds 2
Ok "sshd started."

# --- 7. Verify ---------------------------------------------------------
Step "Verifying"
$svc = Get-Service sshd
if ($svc.Status -eq 'Running') { Ok "Service RUNNING" } else { Bad "Service $($svc.Status)" }

$listen = Get-NetTCPConnection -LocalPort $SshPort -State Listen -ErrorAction SilentlyContinue
if ($listen) { Ok "Port $SshPort LISTENING on $($listen.LocalAddress -join ',')" } else { Bad "Port NOT listening" }

$rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if ($rule -and $rule.Enabled -eq 'True') { Ok "Firewall ENABLED ($($rule.Profile))" } else { Bad "Firewall rule missing" }

$t = Test-NetConnection -ComputerName '127.0.0.1' -Port $SshPort -WarningAction SilentlyContinue
if ($t.TcpTestSucceeded) { Ok "Local SSH test OK" } else { Bad "Local SSH test FAILED" }

# --- 8. IPs (default-route lookup) -------------------------------------
Step "Detecting IPs"

function Get-PrimaryLocalIp {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Sort-Object RouteMetric | Select-Object -First 1
    if ($route) {
        $ip = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } |
               Select-Object -First 1).IPAddress
        if ($ip) { return $ip }
    }
    return (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.AddressState -eq 'Preferred' } |
            Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress
}

$LocalIp = Get-PrimaryLocalIp

$PublicIp = $null
try { $PublicIp = (& curl.exe -s --max-time 8 ifconfig.me).Trim() } catch {}
if ($PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    try { $PublicIp = (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { $PublicIp = '<UNKNOWN>' }
}

# Detect CGNAT: if public IP is in private ranges, we're behind CGNAT
$cgnat = $false
if ($PublicIp -match '^(10\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { $cgnat = $true }

Ok "Public IP : $PublicIp"
Ok "Local  IP : $LocalIp"
if ($cgnat) { Warn "Public IP looks private — likely behind CGNAT. Port forwarding will NOT work." }

# --- 9. FINAL ----------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH READY — DETECTED VALUES" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ("  Username        : {0}" -f $AdminUser)
Write-Host ("  Username source : {0}" -f $userSource)
Write-Host ("  Username SID    : {0}" -f $user.SID.Value)
Write-Host ("  Password        : {0}" -f $(if ($isDomainAccount) { '<YOUR DOMAIN PASSWORD>' } else { $NewPassword }))
Write-Host ("  Port            : {0}" -f $SshPort)
Write-Host ("  Public IP       : {0}" -f $PublicIp)
Write-Host ("  Local  IP       : {0}" -f $LocalIp)
Write-Host ""
Write-Host "  >>> CONNECT FROM ANOTHER PC OVER THE INTERNET:" -ForegroundColor Cyan
Write-Host ("      ssh {0}@{1}" -f $AdminUser, $PublicIp) -ForegroundColor White
Write-Host ""
Write-Host "  >>> CONNECT FROM SAME LAN:" -ForegroundColor Cyan
Write-Host ("      ssh {0}@{1}" -f $AdminUser, $LocalIp) -ForegroundColor White
Write-Host ""
Write-Host "  All IPv4 on this box:" -ForegroundColor DarkGray
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notmatch '^127\.' } |
    Select-Object IPAddress, InterfaceAlias |
    Format-Table -AutoSize | Out-String | Write-Host

if ($cgnat) {
    Write-Host "  [!] CGNAT detected — port forwarding on your router will NOT work." -ForegroundColor Yellow
    Write-Host "      Use a tunnel instead:" -ForegroundColor Yellow
    Write-Host "        ngrok tcp $SshPort" -ForegroundColor White
    Write-Host "        (then: ssh $AdminUser@<ngrok-host> -p <ngrok-port>)" -ForegroundColor White
} elseif ($PublicIp -ne $LocalIp) {
    Write-Host "  [!] If external SSH times out, forward TCP $SshPort on your router" -ForegroundColor Yellow
    Write-Host "      to $LocalIp (this PC's LAN IP)." -ForegroundColor Yellow
}
Write-Host "================================================================" -ForegroundColor Green