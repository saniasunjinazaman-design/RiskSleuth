#!/usr/bin/env python3
"""
RiskSleuth (minimal) - Collect nmap, whatweb, nikto -> check against local vuln rule file -> produce report.json and report.md
Updated: includes a friendly help menu when run with no arguments or with --help
"""

import os, sys, argparse, subprocess, json, shutil
from datetime import datetime
import time

# Config
BASE_OUTPUT = "Results_output"
LOCAL_VULN_DB_FILE = "local_vuln_db.json"
TOOL_NAME = "RiskSleuth (minimal)"
VERSION = "1.1"

# Helpers
def now_ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_mkdir(p):
    os.makedirs(p, exist_ok=True)

def tool_exists(name):
    return shutil.which(name) is not None

def run_cmd_save(cmd, outpath, timeout=None):
    """Run command and save combined stdout/stderr to outpath. Return stdout text."""
    print(f"[+] Running: {cmd}")
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        out = (out or "") + "\n[timeout]"
    # write out
    with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
        f.write(f"$ {cmd}\n\n")
        f.write(out or "")
    return out or ""

# Scanners (only the three)
def nmap_scan(target, outdir):
    out = os.path.join(outdir, "nmap.txt")
    cmd = f"nmap -Pn -sV {target}"
    return run_cmd_save(cmd, out, timeout=900), out

def whatweb_scan(target, outdir):
    out = os.path.join(outdir, "whatweb.txt")
    if tool_exists("whatweb"):
        cmd = f"whatweb --no-errors {target}"
        return run_cmd_save(cmd, out, timeout=300), out
    else:
        with open(out, "w") as f: f.write("whatweb not installed\n")
        return "whatweb not installed\n", out

def nikto_scan(target, outdir):
    out = os.path.join(outdir, "nikto.txt")
    if tool_exists("nikto"):
        cmd = f"nikto -h {target}"
        return run_cmd_save(cmd, out, timeout=900), out
    else:
        with open(out, "w") as f: f.write("nikto not installed\n")
        return "nikto not installed\n", out

# Vulnerability rule matchers
def load_vuln_db(path=LOCAL_VULN_DB_FILE):
    if not os.path.exists(path):
        # default minimal DB if not present
        db = {
            "apache": {"score":7, "note":"Apache detected; check version CVEs."},
            "php": {"score":8, "note":"PHP detected; older versions may be EoL."},
            "wordpress": {"score":9, "note":"WordPress present; check plugins/themes."},
            "mysql": {"score":6, "note":"MySQL detected; verify credentials/patches."},
            "ssh": {"score":3, "note":"SSH open; verify access control and keys."}
        }
        with open(path,"w") as f:
            json.dump(db, f, indent=2)
        return db
    else:
        with open(path,"r") as f:
            return json.load(f)

def find_matches_in_text(text, vuln_db):
    text_l = text.lower()
    matches = []
    for key, info in vuln_db.items():
        if key.lower() in text_l:
            matches.append({"key": key, "score": info.get("score",5), "note": info.get("note","")})
    # Additional heuristics
    if "/phpinfo.php" in text_l or "phpinfo(" in text_l:
        matches.append({"key":"phpinfo_disclosure", "score":8, "note":"/phpinfo.php disclosure found"})
    # nmap open port heuristic
    open_count = text_l.count("open")
    if open_count > 0:
        matches.append({"key":"open_ports", "score":min(3*open_count, 20), "note":f"{open_count} 'open' occurrences"})
    return matches

# Scoring
def compute_total_score(matches):
    total = 0
    for m in matches:
        total += m.get("score",0)
    total = max(0, min(total, 100))
    if total >= 70:
        severity = "Critical"
    elif total >= 40:
        severity = "High"
    elif total >= 15:
        severity = "Medium"
    else:
        severity = "Low"
    return total, severity

# Outputs
def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def write_md(path, info):
    lines = []
    lines.append(f"# {TOOL_NAME} - Risk Report for {info['target']}")
    lines.append(f"**Generated:** {info['timestamp']}")
    lines.append(f"**Operator:** {info.get('operator','unknown')}\n")
    lines.append("## Summary")
    lines.append(f"- Numeric score: **{info['numeric_score']}**")
    lines.append(f"- Severity: **{info['severity']}**\n")
    lines.append("## Findings")
    if info['findings']:
        for f in info['findings']:
            lines.append(f"- {f['key']}: score {f['score']} — {f.get('note','')}")
    else:
        lines.append("- No findings detected by rule-set.")
    lines.append("\n## Raw outputs (in raw/)")
    lines.append("- nmap.txt")
    lines.append("- whatweb.txt")
    lines.append("- nikto.txt")
    lines.append("\n## Notes")
    lines.append(info.get("notes","Authorized scan; retention 90 days"))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n\n".join(lines))

# Help menu (printed when run without args)
def print_help_menu():
    banner = r"""
  ____  _           _  ____  _           _     
 |  _ \(_) ___  ___| |/ ___|| |__   ___ | |__  
 | |_) | |/ _ \/ __| | |    | '_ \ / _ \| '_ \ 
 |  _ <| |  __/ (__| | |___ | | | | (_) | |_) |
 |_| \_\_|\___|\___|_|\____||_| |_|\___/|_.__/ 
            RiskSleuth (minimal)  v{ver}
    """.format(ver=VERSION)
    print(banner)
    print("A beginner-friendly risk-identification tool. Runs nmap, whatweb, nikto,")
    print("matches raw outputs against a local rule file, and generates report.json + report.md")
    print("\nUSAGE:")
    print("  sudo ./risksleuth_minimal.py --target <TARGET> [--operator NAME] [--authorized NAME]")
    print("\nOPTIONS:")
    print("  --target       Single target (IP or domain) [required]")
    print("  --operator     Operator name (optional)")
    print("  --authorized   Who authorized this test (name/email) (optional)")
    print("  -h, --help     Show argparse help")
    print("  --version      Show tool version")
    print("\nEXAMPLES:")
    print("  sudo ./risksleuth_minimal.py --target testphp.vulnweb.com --operator Fuad --authorized 'IT Manager'")
    print("  sudo ./risksleuth_minimal.py --target 192.168.1.10")
    print("\nOUTPUT (per run):")
    print("  Results_output/<target>_<YYYYmmdd_HHMMSS>/")
    print("    raw/nmap.txt")
    print("    raw/whatweb.txt")
    print("    raw/nikto.txt")
    print("    report.json")
    print("    report.md")
    print("    README.txt (authorization + meta)\n")
    print("Notes:")
    print(" - Only run against systems you own or have explicit authorization to test.")
    print(" - The local rule file is:", LOCAL_VULN_DB_FILE)
    print(" - To edit matching rules, update the JSON file above.\n")

# Main
def run(target, operator=None, authorized=None, base_output=BASE_OUTPUT):
    ts = now_ts()
    clean = target.replace(":", "_").replace("/", "_")
    outdir = os.path.join(base_output, f"{clean}_{ts}")
    rawdir = os.path.join(outdir, "raw")
    safe_mkdir(rawdir)

    # README
    with open(os.path.join(outdir,"README.txt"), "w") as f:
        f.write(f"Tool: {TOOL_NAME}\nTarget: {target}\nTimestamp: {ts}\nOperator: {operator or 'unknown'}\nAuthorized: {authorized or 'Unknown (ensure written authorization)'}\n")

    # Run the three scans
    nmap_out_text, nmap_path = nmap_scan(target, rawdir)
    what_out_text, what_path = whatweb_scan(target, rawdir)
    nikto_out_text, nikto_path = nikto_scan(target, rawdir)

    # Aggregate text for matching
    aggregate = "\n".join([nmap_out_text, what_out_text, nikto_out_text])

    # Load vuln DB and match
    vuln_db = load_vuln_db()
    matches = find_matches_in_text(aggregate, vuln_db)

    # Compute score
    numeric_score, severity = compute_total_score(matches)

    # Prepare report object
    report = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "operator": operator,
        "summary": {"numeric_score": numeric_score, "severity": severity},
        "findings": matches,
        "tool_files": {"nmap":"raw/nmap.txt","whatweb":"raw/whatweb.txt","nikto":"raw/nikto.txt"},
        "notes": f"Authorized: {authorized or 'Unknown'}; Generated by {TOOL_NAME}"
    }

    # Write outputs
    write_json(os.path.join(outdir, "report.json"), report)
    write_md(os.path.join(outdir, "report.md"), {"target":target,"timestamp":report["timestamp"],"operator":operator,"numeric_score":numeric_score,"severity":severity,"findings":matches,"notes":report["notes"]})

    print(f"[+] Done. Results saved to: {outdir}")
    return outdir

# CLI
def parse_args():
    p = argparse.ArgumentParser(add_help=False, description="RiskSleuth (minimal) - collect nmap/whatweb/nikto and report using local vuln rules")
    # We'll handle help manually if no args provided
    p.add_argument("--target", help="Target IP or domain")
    p.add_argument("--operator", help="Operator name")
    p.add_argument("--authorized", help="Who authorized this test (name/email)")
    p.add_argument("--version", action="store_true", help="Show tool version")
    p.add_argument("-h", "--help", action="store_true", help="Show help")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # If user invoked with no args or asked for help/version, show menu and exit
    if len(sys.argv) == 1 or args.help:
        print_help_menu()
        sys.exit(0)
    if args.version:
        print(f"{TOOL_NAME} version {VERSION}")
        sys.exit(0)

    # require target
    if not args.target:
        print("[!] Missing --target. Run without arguments to see help.")
        sys.exit(1)

    run(args.target, operator=args.operator, authorized=args.authorized)
