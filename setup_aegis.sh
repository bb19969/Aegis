#!/bin/bash
set -e
# ---------- Colors ----------
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; BLUE="\033[1;34m"; CYAN="\033[1;36m"; RESET="\033[0m"

# ---------- Banner ----------
clear
echo -e "${CYAN}"
echo "#############################################"
echo "#                                           #"
echo "#                 Aegis                     #"
echo "#      Automated Bug Bounty Recon Tool      #"
echo "#                                           #"
echo "#############################################"
echo -e "${RESET}"
echo -e "${GREEN}[+] Starting Aegis Installer...${RESET}\n"

# ---------- Ensure ~/tools exists ----------
mkdir -p ~/tools

# ---------- Update system ----------
echo -e "${BLUE}[*] Updating system packages...${RESET}"
sudo apt update -y >/dev/null 2>&1
sudo apt upgrade -y >/dev/null 2>&1
sudo apt install -y python3 python3-pip curl wget unzip ca-certificates build-essential jq >/dev/null 2>&1

# ---------- Install Go ----------
echo -e "${BLUE}[*] Installing latest Go...${RESET}"
LATEST_TAG=$(curl -s https://go.dev/VERSION?m=text | head -n1)
GO_TARBALL="${LATEST_TAG}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go || true
curl -sL -o /tmp/go.tgz "https://go.dev/dl/${GO_TARBALL}" >/dev/null 2>&1
sudo tar -C /usr/local -xzf /tmp/go.tgz
rm -f /tmp/go.tgz
if ! grep -q '/usr/local/go/bin' ~/.bashrc ; then
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ---------- Install Go tools ----------
echo -e "${BLUE}[*] Installing recon tools...${RESET}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest >/dev/null 2>&1
go install -v github.com/projectdiscovery/katana/cmd/katana@latest >/dev/null 2>&1
go install -v github.com/tomnomnom/assetfinder@latest >/dev/null 2>&1
go install -v github.com/tomnomnom/gf@latest >/dev/null 2>&1
go install -v github.com/lc/gau/v2/cmd/gau@latest >/dev/null 2>&1
go install -v github.com/tomnomnom/waybackurls@latest >/dev/null 2>&1
go install -v github.com/sensepost/gowitness@latest >/dev/null 2>&1

for tool in subfinder httpx nuclei naabu katana assetfinder gf gau waybackurls gowitness; do
  if [ -f ~/go/bin/$tool ]; then ln -sf ~/go/bin/$tool ~/tools/$tool; fi
done

# ---------- Install Findomain ----------
echo -e "${BLUE}[*] Installing Findomain (system-wide)...${RESET}"
curl -sL -o /tmp/findomain.zip https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -oq /tmp/findomain.zip -d /tmp/
sudo mv -f /tmp/findomain /usr/local/bin/findomain
sudo chmod +x /usr/local/bin/findomain
rm -f /tmp/findomain.zip

# ---------- GF Patterns ----------
echo -e "${BLUE}[*] Adding GF patterns...${RESET}"
mkdir -p ~/.gf
curl -sL https://github.com/1ndianl33t/Gf-Patterns/archive/refs/heads/master.zip -o /tmp/gf.zip
unzip -oq /tmp/gf.zip -d /tmp/
mv -f /tmp/Gf-Patterns-master/*.json ~/.gf/ || true
rm -rf /tmp/gf.zip /tmp/Gf-Patterns-master

# ---------- Setup Aegis ----------
echo -e "${BLUE}[*] Setting up Aegis...${RESET}"
mkdir -p ~/tools/aegis/recon
cd ~/tools/aegis

# ---------- Pull files from GitHub ----------
REPO_URL="https://raw.githubusercontent.com/<your-username>/<your-repo>/main"

echo -e "${BLUE}[*] Fetching cli.py...${RESET}"
curl -sL $REPO_URL/cli.py -o cli.py
chmod +x cli.py

echo -e "${BLUE}[*] Fetching requirements.txt...${RESET}"
curl -sL $REPO_URL/requirements.txt -o requirements.txt

echo -e "${BLUE}[*] Fetching .env.example...${RESET}"
curl -sL $REPO_URL/.env.example -o .env.example

# ---------- Python deps ----------
echo -e "${BLUE}[*] Installing Python dependencies...${RESET}"
pip3 install -r requirements.txt >/dev/null 2>&1

# ---------- Alias ----------
if ! grep -q 'alias aegis=' ~/.bashrc ; then
  echo "alias aegis='python3 ~/tools/aegis/cli.py'" >> ~/.bashrc
fi
source ~/.bashrc || true

echo
echo -e "${GREEN}[✓] Aegis setup complete.${RESET}"
echo -e "${YELLOW}    • aegis --debug${RESET}"
echo -e "${YELLOW}    • aegis ai \"do a fast scan on Tesla\"${RESET}"
echo -e "${YELLOW}    • aegis start https://hackerone.com/tesla?type=team --mode deep --ai --screenshots${RESET}"
echo -e "${YELLOW}    • aegis server --port 8080${RESET}"
echo -e "${YELLOW}    • aegis ssh user@vps \"quick scan on Shopify\"${RESET}"
echo
