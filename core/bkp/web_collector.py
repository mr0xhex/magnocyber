#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse


def _timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _normalize_target(target: str) -> Dict[str, str]:
    original = target.strip()
    parsed = urlparse(original if "://" in original else f"https://{original}")
    scheme = parsed.scheme or "https"
    host = parsed.netloc or parsed.path.split("/")[0]
    base_url = f"{scheme}://{host}"
    return {
        "input": original,
        "base_url": base_url,
        "host": host,
    }


def _append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8", errors="replace") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def _run_command(name: str, command: List[str], raw_file: Path, timeout: int = 300) -> None:
    started = dt.datetime.now().isoformat(timespec="seconds")
    _append(raw_file, f"\n===== {name.upper()} =====")
    _append(raw_file, f"STARTED_AT: {started}")
    _append(raw_file, "COMMAND: " + " ".join(command))

    binary = command[0]
    if shutil.which(binary) is None:
        _append(raw_file, f"STATUS: missing")
        _append(raw_file, f"STDERR: Tool not found: {binary}")
        _append(raw_file, f"FINISHED_AT: {dt.datetime.now().isoformat(timespec='seconds')}\n")
        return

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        _append(raw_file, f"STATUS: completed")
        _append(raw_file, f"RETURNCODE: {result.returncode}")
        _append(raw_file, "\n--- STDOUT ---")
        _append(raw_file, result.stdout[:500_000] if result.stdout else "")
        _append(raw_file, "\n--- STDERR ---")
        _append(raw_file, result.stderr[:200_000] if result.stderr else "")
    except subprocess.TimeoutExpired as exc:
        _append(raw_file, "STATUS: timeout")
        _append(raw_file, "\n--- STDOUT BEFORE TIMEOUT ---")
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        _append(raw_file, stdout[:300_000])
        _append(raw_file, "\n--- STDERR BEFORE TIMEOUT ---")
        _append(raw_file, stderr[:100_000])
    finally:
        _append(raw_file, f"FINISHED_AT: {dt.datetime.now().isoformat(timespec='seconds')}\n")


def _write_wordlist(path: Path) -> None:
    words = [
        "api", "api/v1", "api/v2", "graphql", "graphiql", "swagger", "swagger-ui",
        "swagger.json", "openapi.json", "docs", "redoc", "admin", "login", "dashboard",
        "backend", "server", "internal", "actuator", "health", "debug", "status", "metrics",
        ".env", ".git/HEAD", "robots.txt", "sitemap.xml", ".well-known/security.txt",
        "backup", "backups", "config", "config.json", "config.yml", "config.yaml",
    ]
    path.write_text("\n".join(words) + "\n", encoding="utf-8")


def build_web_pentest_commands(target: Dict[str, str], reports_dir: Path) -> List[Dict[str, object]]:
    base_url = target["base_url"]
    host = target["host"]

    api_wordlist = reports_dir / "magno_web_api_words.txt"
    _write_wordlist(api_wordlist)

    common_wordlist_candidates = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    common_wordlist = next((w for w in common_wordlist_candidates if Path(w).exists()), str(api_wordlist))

    return [
        {"name": "whatweb", "command": ["whatweb", "-a", "3", base_url], "timeout": 120},
        {"name": "httpx", "command": ["httpx", "-u", base_url, "-status-code", "-title", "-tech-detect", "-web-server", "-follow-host-redirects"], "timeout": 120},
        {"name": "nmap_http", "command": ["nmap", "-sV", "-Pn", "-p", "80,443,8080,8443,8000,8888,9000", "--script", "http-title,http-server-header,http-headers,http-methods", host], "timeout": 240},
        {"name": "katana", "command": ["katana", "-u", base_url, "-silent", "-jc", "-kf", "all", "-d", "3"], "timeout": 300},
        {"name": "gau", "command": ["gau", host], "timeout": 180},
        {"name": "waybackurls", "command": ["waybackurls", host], "timeout": 180},
        {"name": "nuclei_technologies", "command": ["nuclei", "-u", base_url, "-tags", "tech", "-silent"], "timeout": 240},
        {"name": "nuclei_exposures", "command": ["nuclei", "-u", base_url, "-tags", "exposure,misconfig,panel,files", "-severity", "info,low,medium,high,critical", "-silent"], "timeout": 420},
        {"name": "nuclei_cves", "command": ["nuclei", "-u", base_url, "-tags", "cve", "-severity", "medium,high,critical", "-silent"], "timeout": 600},
        {"name": "testssl", "command": ["testssl", "--fast", "--warnings", "batch", base_url], "timeout": 420},
        {"name": "nikto", "command": ["nikto", "-h", base_url, "-nointeractive"], "timeout": 420},
        {"name": "ffuf_api_surface", "command": ["ffuf", "-u", f"{base_url}/FUZZ", "-w", str(api_wordlist), "-mc", "200,204,301,302,307,308,401,403,405", "-t", "10", "-rate", "50"], "timeout": 300},
        {"name": "ffuf_common", "command": ["ffuf", "-u", f"{base_url}/FUZZ", "-w", common_wordlist, "-mc", "200,204,301,302,307,308,401,403,405", "-t", "20", "-rate", "100"], "timeout": 600},
        {"name": "feroxbuster", "command": ["feroxbuster", "-u", base_url, "-w", common_wordlist, "-k", "-x", "php,js,json,txt,zip,bak,old,conf,config,yml,yaml", "--depth", "2", "--rate-limit", "50"], "timeout": 700},
        {"name": "wpscan_detect", "command": ["wpscan", "--url", base_url, "--no-update", "--detection-mode", "mixed"], "timeout": 360},
    ]


def run(target: str, mode: str, reports_dir: str = "reports", run_id: Optional[str] = None) -> Dict[str, str]:
    if mode != "pentest":
        raise ValueError(f"web_collector currently supports only mode=pentest, received: {mode}")

    normalized = _normalize_target(target)
    reports = Path(reports_dir)
    reports.mkdir(parents=True, exist_ok=True)

    timestamp = run_id or _timestamp()
    raw_file = reports / f"web_{mode}_{normalized['host']}_{timestamp}_raw.txt"

    header = f"""MAGNO CYBER RAW EVIDENCE
MODE: {mode}
DOMAIN: web
TARGET_INPUT: {normalized['input']}
TARGET_BASE_URL: {normalized['base_url']}
TARGET_HOST: {normalized['host']}
TIMESTAMP: {timestamp}

COLLECTOR_RULES:
- Collector collects raw evidence only.
- Collector does not decide findings.
- Collector does not generate CVEs.
- Qwen will analyze this raw evidence later.
"""
    raw_file.write_text(header, encoding="utf-8")

    commands = build_web_pentest_commands(normalized, reports)
    for item in commands:
        _run_command(
            name=str(item["name"]),
            command=list(item["command"]),
            raw_file=raw_file,
            timeout=int(item["timeout"]),
        )

    _append(raw_file, "\n===== COLLECTION FINISHED =====")
    _append(raw_file, f"FINISHED_AT: {dt.datetime.now().isoformat(timespec='seconds')}")

    return {
        "raw_file": str(raw_file),
        "timestamp": timestamp,
        "target_host": normalized["host"],
    }
