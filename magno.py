#!/usr/bin/env python3

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"


def build_prompt(target, mode, domain):
    return f"""
Respond ONLY with valid JSON.

You are WhiteRabbit Neo, a cybersecurity specialist used by Ignis.

Ignis provided the following operator input:

target: {target}
mode: {mode}
domain: {domain}

Important:
The operator input itself is valid evidence.
You may use target, mode, and domain as known facts.
Do not infer anything beyond them.

Mode meanings:
- recon: collect initial evidence and understand the target.
- pentest: analyze evidence to identify possible vulnerabilities.
- attack-surface: identify exposed assets and reachable components.

Rules:
- Never claim to accessed the target.
- Never invent technologies, users, business context, firewall, WAF, OS, authentication, or vulnerabilities.
- If something was not observed, mark it as unknown.
- Do not recommend mitigations.
- Do not create vulnerability findings in recon mode.
- Recon mode must focus on evidence collection.
- Fill every field.
- Do not use markdown.
- Do not add extra text.

Return exactly this JSON structure:

{{
  "target": "{target}",
  "mode": "{mode}",
  "domain": "{domain}",
  "objective": "Collect initial evidence and understand the target.",
  "known_facts": [
    "The operator provided the target: {target}",
    "The operator selected mode: {mode}",
    "The operator selected domain: {domain}"
  ],
  "unknowns": [
    "HTTP response status",
    "HTTP response headers",
    "Page title",
    "HTML content",
    "Technologies in use",
    "Public routes",
    "Authentication requirements"
  ],
  "missing_evidence": [
    "HTTP response",
    "HTTP headers",
    "Initial HTML",
    "Discovered links",
    "Technology fingerprinting"
  ],
  "recommended_collection": [
    "Send a safe HTTP GET request to the target",
    "Collect HTTP status code",
    "Collect response headers",
    "Collect page title",
    "Collect initial HTML sample",
    "Extract public links from HTML"
  ],
  "initial_tracks": [
    "HTTP baseline collection",
    "Technology discovery",
    "Public route mapping",
    "Authentication surface identification"
  ],
  "confidence": "medium"
}}
""".strip()

def run_rabbit(prompt):
    result = subprocess.run(
        ["ollama", "run", "rabbit-direto", prompt],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return result.stdout.strip()


def save_report(content, target, mode, domain):
    REPORTS_DIR.mkdir(exist_ok=True)

    safe_target = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"{timestamp}_{domain}_{mode}_{safe_target}.json"
    path = REPORTS_DIR / filename

    path.write_text(content, encoding="utf-8")
    return path


def main():
    parser = argparse.ArgumentParser(description="Ignis - Cyber Investigation Orchestrator")

    parser.add_argument("--target", required=True, help="Target URL, domain, IP or asset")
    parser.add_argument("--mode", required=True, choices=["recon", "pentest", "attack-surface"])
    parser.add_argument("--domain", required=True, choices=["web", "network", "cloud", "identity"])

    args = parser.parse_args()

    prompt = build_prompt(args.target, args.mode, args.domain)
    response = run_rabbit(prompt)
    report_path = save_report(response, args.target, args.mode, args.domain)

    print(response)
    print(f"\n[+] Report saved to: {report_path}")


if __name__ == "__main__":
    main()
