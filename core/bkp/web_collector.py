#!/usr/bin/env python3

import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def fix_mojibake(text):
    if not text:
        return text

    try:
        return text.encode("latin1").decode("utf-8")
    except Exception:
        return text


def collect_http_evidence(target):
    response = requests.get(
        target,
        timeout=15,
        allow_redirects=True,
        headers={
            "User-Agent": "MagnoCyber/0.1 recon collector"
        }
    )

    detected_encoding = response.apparent_encoding or response.encoding or "utf-8"

    html = response.content.decode(
        detected_encoding,
        errors="replace"
    )

    soup = BeautifulSoup(html, "html.parser")

    title = soup.title.string.strip() if soup.title and soup.title.string else None
    title = fix_mojibake(title)

    links = []

    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if href:
            links.append(urljoin(response.url, href))

    return {
        "collector": "web",
        "target": target,
        "status_code": response.status_code,
        "final_url": response.url,
        "encoding": response.encoding,
        "apparent_encoding": response.apparent_encoding,
        "used_encoding": detected_encoding,
        "title": title,
        "headers": dict(response.headers),
        "links": links,
        "html_sample": html[:5000]
    }


def extract_asset_hints(evidence):
    html_sample = evidence.get("html_sample", "")
    soup = BeautifulSoup(html_sample, "html.parser")

    assets = []

    for script in soup.find_all("script", src=True):
        assets.append(script.get("src"))

    for link in soup.find_all("link", href=True):
        href = link.get("href")
        rel = link.get("rel", [])

        if "stylesheet" in rel or href.endswith((".css", ".js", ".svg", ".ico")):
            assets.append(href)

    return assets


def compact_web_evidence_for_analysis(evidence):
    headers = evidence.get("headers", {})
    asset_hints = extract_asset_hints(evidence)

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
        "asset_hints": asset_hints
    }


def build_web_planning_prompt(target, mode):
    return f"""
Respond ONLY with valid JSON.

You are WhiteRabbit Neo, a cybersecurity specialist used by MagnoCyber.

Target: {target}
Mode: {mode}
Domain: web

Focus only on web reconnaissance.

Rules:
- Never claim to have accessed the target.
- Never invent technologies, vulnerabilities, users, business context, firewall, WAF, or OS.
- Recon mode must focus on evidence collection.
- Do not recommend mitigations.
- Do not use markdown.
- Do not add extra text.

Return exactly this JSON structure:

{{
  "target": "{target}",
  "mode": "{mode}",
  "domain": "web",
  "objective": "Collect initial web evidence and understand the target.",
  "known_facts": [
    "The operator provided the target: {target}",
    "The operator selected mode: {mode}",
    "The operator selected domain: web"
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
    "Static assets",
    "Technology fingerprinting"
  ],
  "recommended_collection": [
    "Send a safe HTTP GET request to the target",
    "Collect HTTP status code",
    "Collect response headers",
    "Collect page title",
    "Collect initial HTML sample",
    "Extract public links from HTML",
    "Extract static asset hints"
  ],
  "initial_tracks": [
    "HTTP baseline collection",
    "Technology discovery",
    "Public route mapping",
    "Authentication surface identification",
    "Static asset discovery"
  ],
  "confidence": "medium"
}}
""".strip()


def build_web_analysis_prompt(target, mode, evidence):
    compact_evidence = compact_web_evidence_for_analysis(evidence)

    evidence_json = json.dumps(
        compact_evidence,
        indent=2,
        ensure_ascii=False
    )

    return f"""
Respond ONLY with valid JSON.

You are WhiteRabbit Neo, a cybersecurity specialist used by MagnoCyber.

Target: {target}
Mode: {mode}
Domain: web

Collected web evidence:

{evidence_json}

Rules:
- Use ONLY collected web evidence.
- Do not invent information.
- If something was not observed, mark it as unknown.
- Do not recommend mitigations.
- Do not create vulnerability findings in recon mode.
- Do not copy the collected evidence back into the response.
- observations must be an array of short strings only.
- unknowns must be an array of short strings only.
- identified_technologies must include observed technologies only.
- confidence must be one of: low, medium, high.
- Do not use markdown.
- Do not add extra text.

Technology identification guidance:
- If the Server field contains cloudflare, identify Cloudflare with high confidence.
- If static assets indicate a bundled JavaScript application, identify JavaScript frontend with medium confidence.
- Only identify technologies directly supported by evidence.

Return exactly this JSON structure:

{{
  "observations": [],
  "confirmed_assets": [],
  "identified_technologies": [],
  "unknowns": [],
  "next_collection_targets": [],
  "confidence": ""
}}
""".strip()


