📌 Project Description – RiskSleuth

RiskSleuth is a beginner-friendly cybersecurity tool designed to identify and report potential risks by analyzing results from popular security scanners such as Nmap, WhatWeb, and Nikto. Instead of overwhelming users with raw technical logs, RiskSleuth applies a set of predefined risk rules to highlight key findings and generate a structured, easy-to-read report.

🔎 Key Features

Log Collection: Collects raw outputs (nmap.txt, whatweb.txt, nikto.txt) for a target.

Rule-Based Analysis: Compares findings against a customizable risk rules file (local_vuln_db.json) containing vulnerability patterns, severity scores, and remediation advice.

Risk Scoring: Assigns severity scores (Low, Medium, High, Critical) to findings for quick prioritization.

Reporting: Produces summary reports (report.json and report.md) for both automation and human review.

Extendable Database: Comes with 50+ default risk rules (e.g., outdated software, weak headers, SQL injection hints, misconfigurations). Users can add their own rules easily.

Beginner-Friendly: Minimal setup, simple CLI usage, and structured outputs suitable for learning cybersecurity fundamentals.

🛠️ Workflow

Run security scans (Nmap, WhatWeb, Nikto).

Store the results inside the raw/ folder for a target.

Launch RiskSleuth → it parses the logs and checks them against the risk rules.

Generates a risk report with identified issues, severity levels, and remediation steps.

📂 Output File System
Results_output/
   └─ <target>_<timestamp>/
         ├─ raw/
         │    ├─ nmap.txt
         │    ├─ whatweb.txt
         │    └─ nikto.txt
         ├─ report.json   # machine-readable findings
         └─ report.md     # human-friendly summary

🎯 Purpose

RiskSleuth is intended as an educational and training tool for students, researchers, and security enthusiasts. It bridges the gap between raw vulnerability scan data and actionable security insights, teaching how vulnerabilities are detected, scored, and mitigated.

⚠️ Note: This project is for defensive and educational use only. It should be used on systems you own or have explicit permission to test.
