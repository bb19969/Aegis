# Aegis
Automated AI-Assisted Bug Bounty Recon Tool

## Overview
Aegis is a modular recon framework designed for bug bounty and penetration testing. It integrates traditional reconnaissance tools with AI-assisted workflows to streamline scope analysis, vulnerability discovery, and reporting.

Key features:
- Scope parsing for HackerOne, Bugcrowd, and Intigriti programs
- Recon pipeline: subfinder, assetfinder, findomain, httpx, naabu, katana, gau, waybackurls, nuclei, gf, gowitness
- Modes: fast, standard, deep
- AI integration: Claude, OpenAI, Gemini, or Ollama (auto-selection)
- AI-generated summary reports
- Optional screenshot capture
- API server and SSH passthrough

---

## Quickstart

```bash
# Clone repo
git clone https://github.com/bb19969/Aegis
cd ~/tools/Aegis

# Install
chmod +x setup_aegis.sh
./setup_aegis.sh

# First test run
aegis --debug
aegis ai "do a fast scan of Tesla"
```

---

## Installation

### Step 1. Clone the repository
```bash
git clone https://github.com/bb19969/Aegis
cd ~/tools/Aegis
```

### Step 2. Run the installer
```bash
chmod +x setup_aegis.sh
./setup_aegis.sh
```

This will:
- Install required Go and Python dependencies
- Install and configure reconnaissance tools
- Create the Aegis directory structure at `~/tools/aegis`
- Add an alias so you can run Aegis with `aegis` from anywhere

---

## Configuration

Copy `.env.example` to `.env` and add your API keys:
```bash
cp ~/tools/aegis/.env.example ~/tools/aegis/.env
```

Supported providers:
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`
- `SECURITYTRAILS_API_KEY`
- `CENSYS_API_ID` / `CENSYS_API_SECRET`
- `SHODAN_API_KEY`
- `VT_API_KEY`

Aegis will automatically select the best available AI provider.

---

## Usage

### Debug tool installation and API keys
```bash
aegis --debug
```

### Run explicit recon on a target
```bash
aegis start https://hackerone.com/tesla?type=team --mode deep --ai --screenshots
```

Modes:
- `--mode fast` – lightweight, minimal recon
- `--mode standard` – balanced recon (default)
- `--mode deep` – full recon with GF pattern matching

### Use natural language
```bash
aegis ai "do a fast scan of Shopify program on HackerOne"
```

### Start API server
```bash
aegis server --port 8080
```

### Run recon remotely over SSH
```bash
aegis ssh user@vps "deep scan Tesla on Bugcrowd"
```

---

## Output

Recon results are stored under:
```
~/tools/aegis/recon/<program>/<timestamp>_<mode>/
```

Example contents:
- `all_subs.txt` – all subdomains
- `alive_urls.txt` – live HTTP services
- `ports.txt` – open ports (naabu)
- `nuclei.txt` – nuclei findings
- `gf_*.txt` – GF pattern matches
- `report.md` – AI-generated summary report

---

## License
This project is provided for educational and research purposes. Use responsibly and only against systems you have permission to test.
