#!/usr/bin/env python3
import os, sys, argparse, subprocess, requests, shutil, json, re
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from threading import Thread

VERSION = "1.0.0"
load_dotenv()

# ---------- helpers ----------
def say(msg): print(msg, flush=True)

def run_cmd(cmd, output_file=None, quiet=True):
    tool = os.path.basename(cmd[0])
    say(f"[*] Running {tool}...")
    try:
        if output_file:
            with open(output_file, "w") as out:
                subprocess.run(cmd, stdout=out,
                               stderr=subprocess.DEVNULL if quiet else None,
                               text=True, check=False)
            return output_file
        else:
            with open(os.devnull, "w") as devnull:
                subprocess.run(cmd, stdout=devnull,
                               stderr=subprocess.DEVNULL if quiet else None,
                               text=True, check=False)
            return None
    except Exception as e:
        say(f"[!] Error running {tool}: {e}")
        return None

def ensure_dir(p): Path(p).mkdir(parents=True, exist_ok=True)
def which(binname): return shutil.which(binname) is not None

# ---------- debug ----------
def debug():
    say("\n=== Aegis Debugger ===")
    tools = ["subfinder","assetfinder","findomain","httpx","nuclei","naabu","katana","gau","waybackurls","gf","gowitness","ollama"]
    for t in tools:
        say(f"{t:12} : {'OK' if which(t) else 'MISSING'}")
    keys = ["ANTHROPIC_API_KEY","OPENAI_API_KEY","GEMINI_API_KEY"]
    for k in keys:
        say(f"{k:22}: {'SET' if os.getenv(k) else 'NOT SET'}")
    say("======================\n")

# ---------- scope parsing ----------
def normalize_host(s):
    s = s.strip().strip("`'\"")
    if not s: return None
    if "://" in s:
        try: host = urlparse(s).netloc
        except: host = s
    else:
        host = s.split()[0]
    host = host.lstrip("*.")  
    host = host.split("/")[0]
    return host if "." in host else None

def parse_hackerone(url):
    r = requests.get(url, timeout=30)
    soup = BeautifulSoup(r.text, "html.parser")
    codes = [normalize_host(code.get_text()) for code in soup.select("div.structured-scope code")]
    return [c for c in codes if c]

def parse_bugcrowd(url):
    r = requests.get(url, timeout=30)
    soup = BeautifulSoup(r.text, "html.parser")
    cells = [normalize_host(td.get_text()) for td in soup.select("table.targets-table td.copyable")]
    return [c for c in cells if c]

def parse_intigriti(url):
    r = requests.get(url, timeout=30)
    soup = BeautifulSoup(r.text, "html.parser")
    items = [normalize_host(item.get_text()) for item in soup.select("div.scope-table__item, td.scope__target")]
    return [c for c in items if c]

def get_scope(url_or_domain):
    if "hackerone.com" in url_or_domain:
        hosts = parse_hackerone(url_or_domain)
    elif "bugcrowd.com" in url_or_domain:
        hosts = parse_bugcrowd(url_or_domain)
    elif "intigriti.com" in url_or_domain:
        hosts = parse_intigriti(url_or_domain)
    else:
        hosts = [normalize_host(url_or_domain)]
    return sorted(set([h for h in hosts if h]))

# ---------- recon wrappers ----------
def subfinder(domain, outdir): return run_cmd(["subfinder","-d",domain,"-all"], os.path.join(outdir,f"{domain}_subfinder.txt"))
def assetfinder(domain, outdir): return run_cmd(["assetfinder","--subs-only",domain], os.path.join(outdir,f"{domain}_assetfinder.txt"))
def findomain(domain, outdir):
    outfile = os.path.join(outdir,f"{domain}_findomain.txt")
    run_cmd(["findomain","-t",domain,"-u",outfile,"-q"], None)
    return outfile

def merge_files(files, outpath):
    lines=set()
    for f in files:
        if f and os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    s=line.strip()
                    if s: lines.add(s)
    with open(outpath,"w") as out:
        out.write("\n".join(sorted(lines)))
    return outpath

def httpx_plain(input_file, outdir):
    urls = os.path.join(outdir,"alive_urls.txt")
    run_cmd(["httpx","-l",input_file,"-silent"], urls)
    full = os.path.join(outdir,"alive_full.txt")
    run_cmd(["httpx","-l",input_file,"-title","-tech-detect","-status-code"], full)
    return urls, full

def extract_hosts_from_urls(urlfile, outdir):
    hosts_path = os.path.join(outdir,"hosts.txt")
    hosts=set()
    if os.path.exists(urlfile):
        with open(urlfile) as f:
            for line in f:
                u=line.strip()
                if not u: continue
                try: netloc = urlparse(u).netloc
                except: netloc=None
                if netloc: hosts.add(netloc)
    with open(hosts_path,"w") as out:
        out.write("\n".join(sorted(hosts)))
    return hosts_path

def naabu_scan(hosts_file, outdir): return run_cmd(["naabu","-l",hosts_file,"-silent"], os.path.join(outdir,"ports.txt"))
def katana_scan(domain, outdir): return run_cmd(["katana","-u",f"https://{domain}","-jc","-silent"], os.path.join(outdir,f"{domain}_katana.txt"))
def gau_scan(domain, outdir): return run_cmd(["gau",domain], os.path.join(outdir,f"{domain}_gau.txt"))
def wayback_scan(domain, outdir): return run_cmd(["waybackurls",domain], os.path.join(outdir,f"{domain}_wayback.txt"))
def nuclei_scan(urls_file, outdir, profile="standard"):
    outfile = os.path.join(outdir,"nuclei.txt")
    args = ["nuclei","-l",urls_file]
    if profile=="fast": args += ["-rate-limit","300"]
    run_cmd(args, outfile)
    return outfile

def gf_patterns(input_file, outdir, pattern):
    outfile = os.path.join(outdir, f"gf_{pattern}.txt")
    cmd = f"cat {input_file} | gf {pattern} > {outfile}"
    run_cmd(["bash","-lc",cmd], None)
    return outfile

def screenshotter(urls_file, outdir):
    sdir = os.path.join(outdir,"screenshots"); ensure_dir(sdir)
    run_cmd(["gowitness","file","-f",urls_file,"-P",sdir], None)
    return sdir

# ---------- AI ----------
def call_ai(prompt):
    try:
        if os.getenv("ANTHROPIC_API_KEY"):
            say("[AI] Using Claude")
            from anthropic import Anthropic
            client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            resp = client.messages.create(model="claude-3-5-sonnet-20240620", max_tokens=800,
                                          messages=[{"role":"user","content":prompt}])
            return resp.content[0].text
        elif os.getenv("OPENAI_API_KEY"):
            say("[AI] Using OpenAI")
            from openai import OpenAI
            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"system","content":"You are an AI recon assistant."},
                          {"role":"user","content":prompt}],
                temperature=0.2
            )
            return resp.choices[0].message.content
        elif os.getenv("GEMINI_API_KEY"):
            say("[AI] Using Gemini")
            import google.generativeai as genai
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel("gemini-1.5-flash")
            resp = model.generate_content(prompt)
            return resp.text
        elif which("ollama"):
            say("[AI] Using Ollama")
            r = subprocess.run(["ollama","run","llama3",prompt], capture_output=True, text=True)
            return r.stdout.strip()
        else:
            say("[AI] No AI available.")
            return None
    except Exception as e:
        say(f"[AI] Error: {e}")
        return None

def ai_interpreter(instruction):
    prompt = f"""
You are an AI that converts natural-language recon instructions into JSON.
Fields:
- program_url
- mode: fast | standard | deep
- screenshots: boolean
- ai: boolean
Instruction: {instruction}
"""
    out = call_ai(prompt)
    try: return json.loads(out.strip())
    except: return {"program_url": instruction, "mode":"standard","screenshots":False,"ai":True}

def ai_reporter(outdir):
    pieces=[]
    for name in ["alive_urls.txt","ports.txt","nuclei.txt","gf_xss.txt","gf_ssrf.txt","gf_sqli.txt"]:
        p=os.path.join(outdir,name)
        if os.path.exists(p):
            with open(p) as f: pieces.append(f"\n### {name}\n{f.read()}\n")
    prompt = "Create a concise bug bounty report from the following outputs:\n" + "".join(pieces)
    report = call_ai(prompt)
    if report:
        rf=os.path.join(outdir,"report.md")
        with open(rf,"w") as f: f.write(report)
        say(f"[AI] Report saved: {rf}")
        return rf

# ---------- recon pipeline ----------
def run_recon(target_url, screenshots=False, use_ai=False, mode="standard"):
    base_dir = Path(__file__).resolve().parent
    recon_dir = base_dir / "recon"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    program_slug = target_url.replace("https://","").replace("http://","").split("/")[0]
    outdir = recon_dir / program_slug / f"{timestamp}_{mode}"
    ensure_dir(outdir)

    say(f"\n=== Aegis v{VERSION} ===")
    say(f"[+] Target: {target_url}")
    say(f"[+] Mode: {mode}")
    say(f"[+] Output: {outdir}\n")

    domains = get_scope(target_url)

    sub_files=[]
    for d in domains:
        sub_files += [subfinder(d,outdir), assetfinder(d,outdir)]
        try: sub_files += [findomain(d,outdir)]
        except: pass
        if mode!="fast":
            katana_scan(d,outdir)
            gau_scan(d,outdir); wayback_scan(d,outdir)

    all_subs = merge_files(sub_files, os.path.join(outdir,"all_subs.txt"))
    alive_urls, alive_full = httpx_plain(all_subs, outdir)
    hosts = extract_hosts_from_urls(alive_urls, outdir)

    if mode!="fast": naabu_scan(hosts, outdir)
    nuclei_scan(alive_urls, outdir, profile=("fast" if mode=="fast" else "standard"))

    endpoints = os.path.join(outdir,"endpoints.txt")
    with open(endpoints,"w") as out:
        for d in domains:
            for suf in ["_katana.txt","_gau.txt","_wayback.txt"]:
                p=os.path.join(outdir,f"{d}{suf}")
                if os.path.exists(p):
                    with open(p) as f: out.writelines(f.readlines())

    if mode=="deep" and os.path.exists(endpoints):
        for pat in ["xss","ssrf","sqli"]:
            gf_patterns(endpoints,outdir,pat)

    if screenshots: screenshotter(alive_urls, outdir)
    if use_ai: ai_reporter(outdir)

    say("\n[+] Recon Complete.")
    say(f"    Outputs in: {outdir}\n")
    return outdir

# ---------- server ----------
def start_server(port=8080):
    from fastapi import FastAPI, Request
    import uvicorn
    app = FastAPI()

    @app.post("/scan")
    async def scan(req: Request):
        data = await req.json()
        plan = ai_interpreter(data.get("instruction",""))
        Thread(target=run_recon, args=(plan["program_url"], plan.get("screenshots",False), plan.get("ai",True), plan.get("mode","standard"))).start()
        return {"status":"started","plan":plan}

    say(f"[+] Aegis server running on 0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)

# ---------- ssh passthrough ----------
def ssh_passthrough(ssh_target, instruction):
    safe = instruction.replace("'", "'\"'\"'")
    remote_cmd = f"python3 ~/tools/aegis/cli.py ai '{safe}'"
    say(f"[+] SSH → {ssh_target}")
    subprocess.run(["ssh", ssh_target, remote_cmd])

# ---------- main ----------
def main():
    p = argparse.ArgumentParser(description="Aegis - AI-Assisted Bug Bounty Recon")
    p.add_argument("--debug", action="store_true", help="Show tool/key status")

    sub = p.add_subparsers(dest="cmd")
    sp = sub.add_parser("start", help="Explicit recon run")
    sp.add_argument("target", help="Target domain or program URL")
    sp.add_argument("--mode", choices=["fast","standard","deep"], default="standard")
    sp.add_argument("--screenshots", action="store_true")
    sp.add_argument("--ai", action="store_true")

    ap = sub.add_parser("ai", help="Natural language run")
    ap.add_argument("instruction", help="e.g. 'do a deep scan of Tesla bug bounty program'")

    srv = sub.add_parser("server", help="API server")
    srv.add_argument("--port", type=int, default=8080)

    shp = sub.add_parser("ssh", help="Run on remote VPS via SSH")
    shp.add_argument("ssh_target", help="user@host")
    shp.add_argument("instruction", help="Natural-language instruction")

    args = p.parse_args()

    if args.debug: return debug()
    if args.cmd=="start": run_recon(args.target, args.screenshots, args.ai, args.mode)
    elif args.cmd=="ai":
        plan=ai_interpreter(args.instruction)
        run_recon(plan["program_url"], plan.get("screenshots",False), plan.get("ai",True), plan.get("mode","standard"))
    elif args.cmd=="server": start_server(args.port)
    elif args.cmd=="ssh": ssh_passthrough(args.ssh_target,args.instruction)
    else: p.print_help()

if __name__=="__main__":
    main()
