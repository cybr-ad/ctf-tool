#Requires -RunAsAdministrator

<#
.SYNOPSIS
    All-in-one OpenSSH Server setup for CTF remote access.
.DESCRIPTION
    1. Installs OpenSSH Server (if missing)
    2. Enables + configures the sshd service
    3. Enables password authentication in sshd_config
    4. Finds the built-in Administrator account (SID -500, works if renamed)
    5. Enables it and sets the password to root@2027
    6. Opens TCP 22 on Domain, Private and Public firewall profiles
    7. Restarts sshd
    8. Detects public + local IP and prints the exact SSH command
#>

$ErrorActionPreference = 'Stop'
$NewPassword = 'root@2027'
$SshPort     = 22

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!] $msg" -ForegroundColor Yellow }

# ---------------------------------------------------------------
# 1. Install OpenSSH Server
# ---------------------------------------------------------------
Write-Step "Installing OpenSSH Server"
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    Write-Ok "OpenSSH Server installed."
} else {
    Write-Ok "OpenSSH Server already installed."
}

# ---------------------------------------------------------------
# 2. Configure sshd_config (password auth + port)
# ---------------------------------------------------------------
Write-Step "Configuring sshd_config"
$sshdCfg = "$env:ProgramData\ssh\sshd_config"
if (-not (Test-Path $sshdCfg)) { New-Item -Path $sshdCfg -ItemType File -Force | Out-Null }

$cfg = Get-Content $sshdCfg
# Remove any commented/active overrides we care about, then append explicit settings
$cfg = $cfg | Where-Object { $_ -notmatch '^\s*#?\s*(PasswordAuthentication|PermitRootLogin|Port)\s' }

$add = @(
    "",
    "# ---- CTF setup ----",
    "Port $SshPort",
    "PasswordAuthentication yes",
    "PermitEmptyPasswords no",
    "UseDNS no",
    "PubkeyAuthentication yes"
)
$add | Add-Content -Path $sshdCfg -Encoding ascii
Write-Ok "sshd_config updated (Port $SshPort, PasswordAuthentication yes)."

# ---------------------------------------------------------------
# 3. Locate the built-in Administrator account (RID 500)
# ---------------------------------------------------------------
Write-Step "Locating built-in Administrator account"
$admin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
if (-not $admin) {
    # Fallback: any user named Administrator (localized builds may rename it)
    $admin = Get-LocalUser | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
}
if (-not $admin) {
    throw "Could not find a built-in Administrator account. Aborting."
}
$AdminUser = $admin.Name
Write-Ok "Found: $AdminUser  (SID $($admin.SID.Value))"

# ---------------------------------------------------------------
# 4. Enable account + set password + no expiry
# ---------------------------------------------------------------
Write-Step "Enabling account and setting password"
if (-not $admin.Enabled) {
    Enable-LocalUser -Name $AdminUser
    Write-Ok "Account was disabled -> enabled."
}
$secPwd = ConvertTo-SecureString $NewPassword -AsPlainText -Force
Set-LocalUser -Name $AdminUser -Password $secPwd -PasswordNeverExpires $true
# Make sure it's in Administrators (some hardened images remove it)
try {
    Add-LocalGroupMember -Group 'Administrators' -Member $AdminUser -ErrorAction SilentlyContinue
} catch {}
Write-Ok "Password set to $NewPassword (never expires)."

# ---------------------------------------------------------------
# 5. Service: start + automatic
# ---------------------------------------------------------------
Write-Step "Enabling and starting sshd"
Set-Service -Name sshd -StartupType Automatic
if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
Write-Ok "sshd is running."

# ---------------------------------------------------------------
# 6. Firewall rule — TCP 22 on Domain/Private/Public
# ---------------------------------------------------------------
Write-Step "Configuring Windows Firewall for TCP $SshPort"
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
    -DisplayName "OpenSSH Server (TCP $SshPort) - All Profiles" `
    -Description "Allow inbound SSH from Domain, Private and Public networks." `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow `
    -LocalPort $SshPort -Profile Domain,Private,Public | Out-Null
Write-Ok "Firewall rule created (Domain, Private, Public)."

# ---------------------------------------------------------------
# 7. Restart sshd so new config takes effect
# ---------------------------------------------------------------
Write-Step "Restarting sshd to apply config"
Restart-Service sshd
Start-Sleep -Seconds 2
Write-Ok "sshd restarted."

# ---------------------------------------------------------------
# 8. Gather IPs
# ---------------------------------------------------------------
Write-Step "Detecting IP addresses"
$PublicIp = $null
try { $PublicIp = (& curl.exe -s --max-time 8 ifconfig.me).Trim() } catch {}
if (-not $PublicIp -or $PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    try { $PublicIp = (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { $PublicIp = '<UNKNOWN>' }
}
$LocalIp = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress
Write-Ok "Public IP : $PublicIp"
Write-Ok "Local  IP : $LocalIp"

# ---------------------------------------------------------------
# 9. Final summary
# ---------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH SERVER IS READY" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Username : $AdminUser"
Write-Host "  Password : $NewPassword"
Write-Host "  Port     : $SshPort"
Write-Host "  Public   : $PublicIp"
Write-Host "  Local    : $LocalIp"
Write-Host ""
Write-Host "  Connect from another machine with:" -ForegroundColor Cyan
Write-Host "      ssh $AdminUser@$PublicIp" -ForegroundColor White
Write-Host ""
Write-Host "  From the same LAN:" -ForegroundColor Cyan
Write-Host "      ssh $AdminUser@$LocalIp" -ForegroundColor White
Write-Host ""
Write-Host "  (If the external connect times out, the router in front of" -ForegroundColor DarkYellow
Write-Host "   this PC still needs TCP $SshPort forwarded to $LocalIp.)" -ForegroundColor DarkYellow
Write-Host "================================================================" -ForegroundColor Green