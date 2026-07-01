#!/usr/bin/env python3

import argparse
import json
import sys

from core.rabbit import run_rabbit
from core.reports import save_report

from core.web_collector import (
    collect_http_evidence,
    build_web_planning_prompt,
    build_web_analysis_prompt
)

from core.dns_collector import (
    collect_dns_evidence,
    build_dns_planning_prompt,
    build_dns_analysis_prompt
)


def safe_json_loads(content):
    cleaned = content.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned.replace("```json", "", 1).strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```", "", 1).strip()

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "error": "Rabbit response was not valid JSON",
            "raw_response": content
        }


def get_domain_handlers(domain):
    if domain == "web":
        return {
            "planning_prompt": build_web_planning_prompt,
            "collector": collect_http_evidence,
            "analysis_prompt": build_web_analysis_prompt
        }

    if domain == "dns":
        return {
            "planning_prompt": build_dns_planning_prompt,
            "collector": collect_dns_evidence,
            "analysis_prompt": build_dns_analysis_prompt
        }

    raise ValueError(f"Unsupported domain: {domain}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="MagnoCyber - Rabbit-guided cybersecurity orchestrator"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target URL or domain"
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["recon", "pentest", "attack-surface"],
        help="Operation mode"
    )

    parser.add_argument(
        "--domain",
        required=True,
        choices=["web", "dns"],
        help="Collection domain"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        handlers = get_domain_handlers(args.domain)

        planning_prompt = handlers["planning_prompt"](
            args.target,
            args.mode
        )

        planning_response = run_rabbit(planning_prompt)
        planning = safe_json_loads(planning_response)

        evidence = handlers["collector"](args.target)

        analysis_prompt = handlers["analysis_prompt"](
            args.target,
            args.mode,
            evidence
        )

        analysis_response = run_rabbit(analysis_prompt)
        analysis = safe_json_loads(analysis_response)

        output = {
            "target": args.target,
            "mode": args.mode,
            "domain": args.domain,
            "planning": planning,
            "evidence": evidence,
            "analysis": analysis
        }

        print(json.dumps(output, indent=2, ensure_ascii=False))

        report_path = save_report(
            json.dumps(output, indent=2, ensure_ascii=False),
            args.target,
            args.mode,
            args.domain
        )

        print(f"\n[+] Report saved to: {report_path}")

    except Exception as error:
        print(f"[!] Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
