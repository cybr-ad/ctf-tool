#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Pwd  = 'root@2027'
$Port = 22

Write-Host "`n[*] Installing OpenSSH Server..." -ForegroundColor Cyan
if ((Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*').State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}

Write-Host "[*] Writing sshd_config (Port 22, PasswordAuthentication yes)..." -ForegroundColor Cyan
$cfg = "$env:ProgramData\ssh\sshd_config"
if (-not (Test-Path $cfg)) { New-Item $cfg -ItemType File -Force | Out-Null }
(Get-Content $cfg) | ? { $_ -notmatch '^\s*#?\s*(Port\s+|PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|UseDNS)\b' } |
    Set-Content $cfg -Encoding Ascii
@(
    "",
    "# --- CTF ---",
    "Port 22",
    "PasswordAuthentication yes",
    "PermitRootLogin yes",
    "PubkeyAuthentication yes",
    "PermitEmptyPasswords no",
    "UseDNS no"
) | Add-Content $cfg -Encoding Ascii

Write-Host "[*] Resolving user..." -ForegroundColor Cyan
$u = Get-LocalUser | ? { $_.SID.Value -match '-500$' } | Select -First 1
if (-not $u) { $u = Get-LocalUser | ? { $_.Name -ieq 'Administrator' } | Select -First 1 }
if (-not $u) { $u = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue }
if (-not $u) { throw "No user found." }
$User = $u.Name
Write-Host "    [+] User: $User" -ForegroundColor Green

$isDomain = $false
try { $isDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch {}

if (-not $isDomain -and (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Setting password to $Pwd..." -ForegroundColor Cyan
    if (-not $u.Enabled) { Enable-LocalUser -Name $User }
    Set-LocalUser -Name $User -Password (ConvertTo-SecureString $Pwd -AsPlainText -Force) -PasswordNeverExpires $true
    try { Add-LocalGroupMember -Group Administrators -Member $User -ErrorAction SilentlyContinue } catch {}
    $ShowPwd = $Pwd
} else {
    Write-Host "    [!] Domain account — use your domain password" -ForegroundColor Yellow
    $ShowPwd = '<YOUR DOMAIN PASSWORD>'
}

Write-Host "[*] Opening firewall TCP 22 (Domain/Private/Public)..." -ForegroundColor Cyan
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -EA SilentlyContinue | Remove-NetFirewallRule -EA SilentlyContinue
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH 22 (All)' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 `
    -Profile Domain,Private,Public | Out-Null

Write-Host "[*] Starting sshd..." -ForegroundColor Cyan
Set-Service sshd -StartupType Automatic
Stop-Service sshd -Force -EA SilentlyContinue
Start-Service sshd
Start-Sleep 2

Write-Host "[*] Verifying..." -ForegroundColor Cyan
$svcOk    = (Get-Service sshd).Status -eq 'Running'
$portOk   = [bool](Get-NetTCPConnection -LocalPort 22 -State Listen -EA SilentlyContinue)
$fwOk     = [bool](Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -EA SilentlyContinue)
$localOk  = (Test-NetConnection 127.0.0.1 -Port 22 -WarningAction SilentlyContinue).TcpTestSucceeded

function Get-PrimaryIp {
    $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | Sort RouteMetric | Select -First 1
    if ($r) {
        $ip = (Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -EA SilentlyContinue |
               ? { $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } |
               Select -First 1).IPAddress
        if ($ip) { return $ip }
    }
    return (Get-NetIPAddress -AddressFamily IPv4 |
            ? { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.AddressState -eq 'Preferred' } |
            Sort InterfaceMetric | Select -First 1).IPAddress
}

$LocalIp  = Get-PrimaryIp
$PublicIp = try { (& curl.exe -s --max-time 8 ifconfig.me).Trim() } catch { '' }
if ($PublicIp -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    $PublicIp = try { (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8).Trim() } catch { '<UNKNOWN>' }
}
$cgnat = $PublicIp -match '^(10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SSH READY  (Port 22)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ("  Service running : {0}" -f $svcOk)  -ForegroundColor $(if($svcOk){'Green'}else{'Red'})
Write-Host ("  Port 22 listen  : {0}" -f $portOk) -ForegroundColor $(if($portOk){'Green'}else{'Red'})
Write-Host ("  Firewall rule   : {0}" -f $fwOk)   -ForegroundColor $(if($fwOk){'Green'}else{'Red'})
Write-Host ("  Localhost SSH   : {0}" -f $localOk)-ForegroundColor $(if($localOk){'Green'}else{'Red'})
Write-Host ""
Write-Host ("  Username  : {0}" -f $User)
Write-Host ("  Password  : {0}" -f $ShowPwd)
Write-Host ("  Port      : 22")
Write-Host ("  Public IP : {0}" -f $PublicIp)
Write-Host ("  Local IP  : {0}" -f $LocalIp)
Write-Host ""
Write-Host "  >>> FROM ANOTHER PC OVER THE INTERNET:" -ForegroundColor Cyan
Write-Host ("      ssh {0}@{1}" -f $User, $PublicIp) -ForegroundColor White
Write-Host ""
Write-Host "  >>> FROM SAME LAN:" -ForegroundColor Cyan
Write-Host ("      ssh {0}@{1}" -f $User, $LocalIp) -ForegroundColor White
Write-Host ""
if ($cgnat) {
    Write-Host "  [!] CGNAT detected — port forward won't work. Use:" -ForegroundColor Yellow
    Write-Host ("      ngrok tcp 22   ->  ssh {0}@<ngrok-host> -p <ngrok-port>" -f $User) -ForegroundColor White
} elseif ($PublicIp -ne $LocalIp) {
    Write-Host "  [!] If external times out, forward TCP 22 on router -> $LocalIp" -ForegroundColor Yellow
}
Write-Host "================================================================" -ForegroundColor Green