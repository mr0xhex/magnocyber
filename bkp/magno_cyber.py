#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

import yaml

from core import web_collector
from core.qwen_engine import analyze_evidence


def load_yaml(path: str) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def normalize_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.netloc or parsed.path.split("/")[0]).lower().strip()


def validate_authorization(target: str, authorization: Dict[str, Any]) -> None:
    engagement = authorization.get("engagement", {})
    if engagement.get("authorized") is not True:
        raise SystemExit("Engagement is not authorized. Set engagement.authorized: true in authorization.yaml")

    target_host = normalize_host(target)
    scope = [str(item).lower().strip() for item in engagement.get("scope", [])]

    allowed = False
    for item in scope:
        scope_host = normalize_host(item)
        if target_host == scope_host or target_host.endswith("." + scope_host):
            allowed = True
            break

    if not allowed:
        raise SystemExit(f"Target out of scope: {target_host}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Magno Cyber orchestrator")
    parser.add_argument("--mode", required=True, choices=["pentest", "redteam"])
    parser.add_argument("--domain", required=True, choices=["web"])
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorization", default="authorization.yaml")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    config = load_yaml(args.config)
    authorization = load_yaml(args.authorization)
    validate_authorization(args.target, authorization)

    reports_dir = config.get("reports", {}).get("directory", "reports")

    if args.domain == "web":
        collection = web_collector.run(
            target=args.target,
            mode=args.mode,
            reports_dir=reports_dir,
        )
        raw_file = collection["raw_file"]
        findings_file = str(Path(reports_dir) / f"web_{args.mode}_{collection['target_host']}_{collection['timestamp']}_findings.json")

        analyze_evidence(
            prompt_file="prompts/web_pentest.txt",
            evidence_file=raw_file,
            output_file=findings_file,
            config=config,
        )

        print(json.dumps({
            "mode": args.mode,
            "domain": args.domain,
            "target": args.target,
            "raw_evidence": raw_file,
            "findings": findings_file,
        }, ensure_ascii=False, indent=2))
        return 0

    raise SystemExit(f"Unsupported domain: {args.domain}")


if __name__ == "__main__":
    raise SystemExit(main())
