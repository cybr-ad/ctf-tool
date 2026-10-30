#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$NewPass = 'root@2027'          # FIX 1: not $Pwd (automatic variable)
$Port    = 22

function Step($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "    [x] $m" -ForegroundColor Red }

# --- 1. Install OpenSSH Server -----------------------------------------
Step "Installing OpenSSH Server"
$sshdExe = "$env:WINDIR\System32\OpenSSH\sshd.exe"
if (-not (Test-Path $sshdExe)) {
    $cap = Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
           Where-Object Name -like 'OpenSSH.Server*' | Select-Object -First 1
    if (-not $cap -or $cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }
    Ok "Installed."
} else { Ok "Already installed." }

# --- 2. Repair ACLs (Error 1067/1053 fix) ------------------------------
Step "Repairing sshd folder ACLs"
$sshData = "$env:ProgramData\ssh"
$sshLogs = "$sshData\logs"
if (Test-Path $sshData) {
    & icacls.exe $sshData /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" 2>&1 | Out-Null
    Ok "ACL: $sshData"
}
if (Test-Path $sshLogs) {
    & icacls.exe $sshLogs /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" 2>&1 | Out-Null
    Ok "ACL: $sshLogs"
}
$cfgPath = "$sshData\sshd_config"
if (Test-Path $cfgPath) {
    & icacls.exe $cfgPath /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" 2>&1 | Out-Null
    Ok "ACL: sshd_config"
}
Get-ChildItem "$sshData\ssh_host_*_key" -ErrorAction SilentlyContinue | ForEach-Object {
    & icacls.exe $_.FullName /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" 2>&1 | Out-Null
}

# --- 3. Write sshd_config ----------------------------------------------
Step "Writing sshd_config"
if (-not (Test-Path $cfgPath)) { New-Item -Path $cfgPath -ItemType File -Force | Out-Null }
# FIX 4: wrap in @() so $cfg is always an array, even if empty
$cfg = @(Get-Content $cfgPath -ErrorAction SilentlyContinue | Where-Object {
    $_ -notmatch '^\s*#?\s*(Port\s+|PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|UseDNS)\b'
})
$block = @(
    "", "# --- CTF bulletproof ---",
    "Port $Port",
    "PasswordAuthentication yes",
    "PermitRootLogin yes",
    "PubkeyAuthentication yes",
    "PermitEmptyPasswords no",
    "UseDNS no"
)
$matchIdx = -1
for ($i = 0; $i -lt $cfg.Count; $i++) {
    if ($cfg[$i] -match '^\s*Match\s') { $matchIdx = $i; break }
}
if ($matchIdx -ge 0) {
    $newCfg = @()
    if ($matchIdx -gt 0) { $newCfg += $cfg[0..($matchIdx - 1)] }
    $newCfg += $block
    $newCfg += $cfg[$matchIdx..($cfg.Count - 1)]
    $newCfg | Set-Content -Path $cfgPath -Encoding Ascii
} else {
    ($cfg + $block) | Set-Content -Path $cfgPath -Encoding Ascii
}
Ok "sshd_config written."

# --- 4. Resolve user ---------------------------------------------------
Step "Resolving user"
$User = $null; $isLocalUser = $true; $source = ''

$u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
if ($u) { $source = 'SID -500' }
if (-not $u) {
    $u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
    if ($u) { $source = 'Name=Administrator' }
}
if (-not $u) {
    $u = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
    if ($u) { $source = 'CurrentUser (local)' }
}
if (-not $u) {
    $u = [pscustomobject]@{
        Name    = $env:USERNAME
        SID     = [pscustomobject]@{ Value = 'DOMAIN' }
        Enabled = $true
    }
    $isLocalUser = $false
    $source = 'CurrentUser (domain)'
}
$User = $u.Name
Ok "User: $User (source: $source)"

# --- 5. Set password ---------------------------------------------------
Step "Configuring password"
$lapsManaged = $false
if ($isLocalUser) {
    try {
        if (-not $u.Enabled) { Enable-LocalUser -Name $User; Ok "Account enabled." }
        $sec = ConvertTo-SecureString $NewPass -AsPlainText -Force
        Set-LocalUser -Name $User -Password $sec -PasswordNeverExpires $true
        Ok "Password set to $NewPass"
        $ShowPwd = $NewPass
        # FIX 7: use well-known SID S-1-5-32-544 for Administrators group (language-independent)
        try {
            $adminGrp = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
            if ($adminGrp) {
                $isMember = Get-LocalGroupMember -Group $adminGrp.Name -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -match "\\$([regex]::Escape($User))$" }
                if (-not $isMember) {
                    Add-LocalGroupMember -Group $adminGrp.Name -Member $User -ErrorAction Stop
                    Ok "Added to Administrators."
                } else { Ok "Already in Administrators." }
            }
        } catch { Warn "Admin group check: $($_.Exception.Message)" }
    } catch {
        Warn "Set-LocalUser failed: $($_.Exception.Message)"
        Warn "Use existing / LAPS password for SSH."
        $ShowPwd = '<EXISTING / LAPS PASSWORD>'
        $lapsManaged = $true
    }
} else {
    # FIX 2: only skip password for actual domain accounts
    Warn "Domain account — use your domain password for SSH."
    $ShowPwd = '<YOUR DOMAIN PASSWORD>'
}

# --- 6. LocalAccountTokenFilterPolicy (UAC token fix) ------------------
Step "Setting LocalAccountTokenFilterPolicy = 1"
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $regPath -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -Force
Ok "Done."

# --- 7. DefaultShell = PowerShell --------------------------------------
Step "Setting DefaultShell to PowerShell"
$shellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path $shellPath) {
    $regKey = 'HKLM:\SOFTWARE\OpenSSH'
    # FIX 3: ensure key exists before writing property
    if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
    New-ItemProperty -Path $regKey -Name 'DefaultShell' -Value $shellPath -PropertyType String -Force | Out-Null
    Ok "DefaultShell = PowerShell."
} else { Warn "PowerShell not found." }

# --- 8. Firewall -------------------------------------------------------
Step "Configuring firewall TCP/$Port"
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName "OpenSSH 22 (All Profiles)" `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $Port `
    -Profile Domain,Private,Public | Out-Null
Ok "Firewall rule created."

# --- 9. Start sshd (retry) ---------------------------------------------
Step "Starting sshd"
Set-Service -Name sshd -StartupType Automatic
$started = $false
for ($a = 1; $a -le 3; $a++) {
    try {
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Start-Service -Name sshd -ErrorAction Stop
        Start-Sleep -Seconds 2
        if ((Get-Service -Name sshd).Status -eq 'Running') { $started = $true; break }
    } catch {
        Warn "Attempt $a failed: $($_.Exception.Message)"
        Start-Sleep -Seconds 2
    }
}
if (-not $started) { Bad "sshd failed to start after 3 attempts."; throw "Service start failed." }
Ok "sshd is running."

# --- 10. Verify --------------------------------------------------------
Step "Verifying"
$svcOk  = (Get-Service -Name sshd).Status -eq 'Running'
$portOk = [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
$fwOk   = [bool](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
$local  = (Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded
if ($svcOk)  { Ok "Service RUNNING" }  else { Bad "Service NOT RUNNING" }
if ($portOk) { Ok "Port $Port LISTENING" } else { Bad "Port NOT LISTENING" }
if ($fwOk)   { Ok "Firewall OK" }       else { Bad "Firewall MISSING" }
if ($local)  { Ok "Local SSH test OK" } else { Bad "Local SSH test FAILED" }

# --- 11. IPs -----------------------------------------------------------
Step "Detecting network"
$LocalIp = $null
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($r) {
    $LocalIp = (Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } |
        Select-Object -First 1).IPAddress
}
if (-not $LocalIp) {
    $LocalIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.AddressState -eq 'Preferred' } |
        Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress
}

# FIX 5: Out-String ensures curl output is a single string before Trim()
$PublicIp = $null
try { $PublicIp = (& curl.exe -s --max-time 8 ifconfig.me 2>$null | Out-String).Trim() } catch {}
if (-not $PublicIp -or $PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    try { $PublicIp = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { $PublicIp = '<UNKNOWN>' }
}
$cgnat = $PublicIp -match '^(10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'
Ok "Public: $PublicIp | Local: $LocalIp"
if ($cgnat) { Warn "CGNAT detected — use ngrok/tunnel." }

# --- 12. Final output --------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH READY (Port 22)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Username : $User"
Write-Host "  Password : $ShowPwd"
Write-Host "  Port     : 22"
Write-Host "  Public IP: $PublicIp"
Write-Host "  Local IP : $LocalIp"
if ($lapsManaged) { Write-Host "  [LAPS] Use LAPS password." -ForegroundColor Yellow }
Write-Host ""
Write-Host "  >>> FROM INTERNET:" -ForegroundColor Cyan
Write-Host "      ssh $User@$PublicIp"
Write-Host ""
Write-Host "  >>> FROM LAN:" -ForegroundColor Cyan
Write-Host "      ssh $User@$LocalIp"
Write-Host ""
if ($cgnat) {
    Write-Host "  [!] CGNAT: run 'ngrok tcp 22' on target." -ForegroundColor Yellow
} elseif ($PublicIp -ne $LocalIp) {
    Write-Host "  [!] Forward TCP 22 on router -> $LocalIp if external fails." -ForegroundColor Yellow
}
Write-Host "================================================================" -ForegroundColor Green
