#!/usr/bin/env bash
# CTF Multi-Category Tool Installation Script (Kali Linux)
# Usage: chmod +x install_ctf_tools.sh && sudo ./install_ctf_tools.sh
set -Eeuo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# Fix for newer Debian/Kali PEP 668 Python restrictions
export PIP_BREAK_SYSTEM_PACKAGES=1

# ---------- Base Environment ----------
log "Updating package lists and installing base build tools ..."
apt update -y
apt install -y build-essential git curl wget python3 python3-pip python3-venv \
  unzip p7zip-full file binutils xxd hexedit jq ruby ruby-dev golang-go openjdk-17-jre

# ---------- 01 Web ----------
log "Installing Web tools ..."
apt install -y ffuf gobuster dirb nikto sqlmap wpscan whatweb
pip3 install --upgrade requests beautifulsoup4

# ---------- 02 Forensics ----------
log "Installing Forensics tools ..."
apt install -y autopsy sleuthkit binwalk foremost exiftool scalpel \
  testdisk photorec
pip3 install --upgrade volatility3

# ---------- 03 Steganography ----------
log "Installing Steganography tools ..."
apt install -y steghide ruby audacity sonic-visualiser
gem install zsteg --no-document

# Fix: StegSolve manual installation (Not in apt)
log "Installing StegSolve manually ..."
mkdir -p /opt/stegsolve ~/bin
wget -q https://github.com/Giotino/stegsolve/releases/latest/download/stegsolve.jar -O /opt/stegsolve/stegsolve.jar
cat << 'EOF' > /usr/local/bin/stegsolve
#!/bin/sh
exec java -jar /opt/stegsolve/stegsolve.jar "$@"
EOF
chmod +x /usr/local/bin/stegsolve

# ---------- 04 Network ----------
log "Installing Network tools ..."
apt install -y wireshark tshark tcpdump nmap netcat-openbsd socat
pip3 install --upgrade scapy

# ---------- 05 Cryptography ----------
log "Installing Cryptography tools ..."
apt install -y hashcat hashcat-data john john-data sagemath openssl libssl-dev
if [[ ! -d /opt/RsaCtfTool ]]; then
  git clone https://github.com/Ganapati/RsaCtfTool.git /opt/RsaCtfTool
fi
pip3 install --upgrade -r /opt/RsaCtfTool/requirements.txt
ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool

# ---------- 06 PWN ----------
log "Installing PWN tools ..."
apt install -y gdb gdb-multiarch radare2 patchelf strace ltrace checksec
pip3 install --upgrade pwntools ropgadget ropper
if [[ ! -d /opt/pwndbg ]]; then
  git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
fi
cd /opt/pwndbg && ./setup.sh
gem install one_gadget --no-document

# ---------- 07 Reverse Engineering ----------
log "Installing Reverse Engineering tools ..."
apt install -y ghidra || warn "ghidra not found in apt sources; you may need to download it manually from the official site."
pip3 install --upgrade angr

# ---------- 08 AI / LLM ----------
log "Installing AI/LLM security tools ..."
pip3 install --upgrade wrg-ai-security-toolkit || warn "Failed to install wrg-ai-security-toolkit."
if [[ ! -d /opt/AIGoat ]]; then
  git clone https://github.com/AISecurityConsortium/AIGoat.git /opt/AIGoat
fi

# ---------- 09 Hardware ----------
log "Installing Hardware/IoT tools ..."
apt install -y binwalk flashrom picocom minicom screen
pip3 install --upgrade chipsec || warn "Failed to install chipsec."

# ---------- 10 Blockchain ----------
log "Installing Blockchain tools ..."
pip3 install --upgrade slither-analyzer mythril
if ! command -v forge &>/dev/null; then
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup || warn "foundryup failed; please check your network and retry."
fi

# ---------- 11 OSINT ----------
log "Installing OSINT tools ..."
apt install -y whois dnsutils nmap exiftool imagemagick curl
pip3 install --upgrade shodan theHarvester || warn "Failed to install theHarvester."

# ---------- 12 Miscellaneous ----------
log "Installing Misc tools ..."
apt install -y cyberchef || {
  warn "cyberchef not found in apt sources. Please install via: sudo apt install cyberchef"
}
pip3 install --upgrade z3-solver pycryptodome

# ---------- Finalization ----------
log "Setting up wordlists ..."
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
fi

# Add ~/bin to PATH if not already present
if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
fi

log "Installation complete. Please run 'source ~/.bashrc' or open a new terminal."
warn "Some tools (like Maltego, Burp Suite Pro) require manual downloading or licensing."
