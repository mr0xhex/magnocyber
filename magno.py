#!/usr/bin/env python3

import argparse
import json

from core.prompts import build_prompt, build_analysis_prompt
from core.rabbit import run_rabbit
from core.reports import save_report
from core.web_collector import collect_http_evidence


def safe_json_loads(content):
    content = content.strip()

    if content.startswith("```json"):
        content = content.removeprefix("```json").strip()

    if content.startswith("```"):
        content = content.removeprefix("```").strip()

    if content.endswith("```"):
        content = content.removesuffix("```").strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {
            "error": "Rabbit response was not valid JSON",
            "raw_response": content
        }


def main():
    parser = argparse.ArgumentParser(
        description="MagnoCyber - Cyber Investigation Orchestrator"
    )

    parser.add_argument("--target", required=True, help="Target URL, domain, IP or asset")
    parser.add_argument("--mode", required=True, choices=["recon", "pentest", "attack-surface"])
    parser.add_argument("--domain", required=True, choices=["web", "network", "cloud", "identity"])

    args = parser.parse_args()

    prompt = build_prompt(args.target, args.mode, args.domain)
    planning_response = run_rabbit(prompt)

    if args.domain == "web":
        evidence = collect_http_evidence(args.target)
    else:
        evidence = {
            "collector": args.domain,
            "target": args.target,
            "error": f"Collector not implemented for domain: {args.domain}"
        }


    analysis_evidence = compact_evidence_for_analysis(evidence)

    analysis_prompt = build_analysis_prompt(
        args.target,
        args.mode,
        args.domain,
        analysis_evidence
    )

    analysis_response = run_rabbit(analysis_prompt)

    output = {
        "target": args.target,
        "mode": args.mode,
        "domain": args.domain,
        "planning": safe_json_loads(planning_response),
        "evidence": evidence,
        "analysis": safe_json_loads(analysis_response),
    }

    report_content = json.dumps(output, indent=2, ensure_ascii=False)
    report_path = save_report(report_content, args.target, args.mode, args.domain)

    print(report_content)
    print(f"\n[+] Report saved to: {report_path}")


def compact_evidence_for_analysis(evidence):
    headers = evidence.get("headers", {})

    return {
        "collector": evidence.get("collector"),
        "target": evidence.get("target"),
        "status_code": evidence.get("status_code"),
        "final_url": evidence.get("final_url"),
        "title": evidence.get("title"),
        "server": headers.get("Server"),
        "content_type": headers.get("Content-Type"),
        "security_headers_present": {
            "strict_transport_security": bool(headers.get("Strict-Transport-Security")),
            "content_security_policy": bool(headers.get("Content-Security-Policy")),
            "x_frame_options": bool(headers.get("X-Frame-Options")),
            "x_content_type_options": bool(headers.get("X-Content-Type-Options")),
            "referrer_policy": bool(headers.get("Referrer-Policy")),
            "permissions_policy": bool(headers.get("Permissions-Policy")),
        },
        "links_count": len(evidence.get("links", [])),
        "links": evidence.get("links", [])[:20],
        "asset_hints": [
            "/assets/index-CYzRzrr0.js",
            "/assets/index-D9RzE5Oi.css"
        ] if "html_sample" in evidence else []
    }



if __name__ == "__main__":
    main()
