#!/usr/bin/env bash
# CTF Multi-Category Tool Installation Script (Kali Linux)
# Usage: chmod +x install_ctf_tools.sh && sudo ./install_ctf_tools.sh
set -Eeuo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# ---------- Base Environment ----------
log "Updating package lists and installing base build tools ..."
apt update -y
apt install -y build-essential git curl wget python3 python3-pip python3-venv \
  unzip p7zip-full file binutils xxd hexedit jq ruby ruby-dev golang-go

# ---------- 01 Web ----------
log "Installing Web tools ..."
# Burp Suite Community is usually pre-installed on Kali; manual download if missing
apt install -y ffuf gobuster dirb nikto sqlmap wpscan whatweb
pip3 install --upgrade requests beautifulsoup4

# ---------- 02 Forensics ----------
log "Installing Forensics tools ..."
apt install -y autopsy sleuthkit binwalk foremost exiftool scalpel \
  testdisk photorec
# Volatility 3
pip3 install --upgrade volatility3

# ---------- 03 Steganography ----------
log "Installing Steganography tools ..."
apt install -y steghide stegsolve ruby
# zsteg
gem install zsteg
# Audio related
apt install -y audacity sonic-visualiser

# ---------- 04 Network ----------
log "Installing Network tools ..."
apt install -y wireshark tshark tcpdump nmap netcat-openbsd socat
pip3 install --upgrade scapy

# ---------- 05 Cryptography ----------
log "Installing Cryptography tools ..."
apt install -y hashcat hashcat-data john john-data sagemath openssl libssl-dev
# RsaCtfTool
if [[ ! -d /opt/RsaCtfTool ]]; then
  git clone https://github.com/Ganapati/RsaCtfTool.git /opt/RsaCtfTool
fi
pip3 install --upgrade -r /opt/RsaCtfTool/requirements.txt
ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool

# ---------- 06 PWN ----------
log "Installing PWN tools ..."
apt install -y gdb gdb-multiarch radare2 patchelf strace ltrace checksec
pip3 install --upgrade pwntools ropgadget ropper
# pwndbg
if [[ ! -d /opt/pwndbg ]]; then
  git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
fi
cd /opt/pwndbg && ./setup.sh
# one_gadget
gem install one_gadget

# ---------- 07 Reverse Engineering ----------
log "Installing Reverse Engineering tools ..."
# Install Ghidra from Kali repos (if available)
apt install -y ghidra || warn "ghidra not found in apt sources; you may need to download it manually from the official site."
pip3 install --upgrade angr

# ---------- 08 AI / LLM ----------
log "Installing AI/LLM security tools ..."
# AI Security Toolkit
pip3 install --upgrade wrg-ai-security-toolkit || true
# AIGoat
if [[ ! -d /opt/AIGoat ]]; then
  git clone https://github.com/AISecurityConsortium/AIGoat.git /opt/AIGoat
fi
# InjectArena etc. are usually obtained via Docker or separate repos; install manually as needed.

# ---------- 09 Hardware ----------
log "Installing Hardware/IoT tools ..."
apt install -y binwalk flashrom picocom minicom screen
pip3 install --upgrade chipsec || true
# Hardsploit depends on hardware needs; install following official docs.

# ---------- 10 Blockchain ----------
log "Installing Blockchain tools ..."
pip3 install --upgrade slither-analyzer mythril
# Foundry (if needed)
if ! command -v forge &>/dev/null; then
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup || warn "foundryup failed; please check your network and retry."
fi

# ---------- 11 OSINT ----------
log "Installing OSINT tools ..."
apt install -y whois dnsutils nmap exiftool imagemagick curl
pip3 install --upgrade shodan theHarvester || true
# Maltego is usually obtained via the official installer and is quite large; install manually if needed.

# ---------- 12 Miscellaneous ----------
log "Installing Misc tools ..."
# CyberChef
apt install -y cyberchef || {
  warn "cyberchef not found in apt sources, attempting direct download from Kali repos ..."
  cd /tmp
  wget -q "http://http.kali.org/pool/main/c/cyberchef/cyberchef_11.3.0-0kali1_amd64.deb" || true
  [[ -f cyberchef_11.3.0-0kali1_amd64.deb ]] && dpkg -i cyberchef_11.3.0-0kali1_amd64.deb || true
  apt install -f -y || true
}
pip3 install --upgrade z3-solver pycryptodome

# ---------- Finalization ----------
log "Setting up wordlists ..."
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
fi

log "Installation complete. Please open a new terminal or run 'source ~/.bashrc' to apply PATH changes."
warn "Some tools (e.g., Ghidra, Maltego, Burp Suite Pro features) may require manual downloading or extra configuration. This script only covers automated installations."