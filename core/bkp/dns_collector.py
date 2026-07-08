#!/usr/bin/env python3

import json
import re
import shutil
import subprocess
from urllib.parse import urlparse
from ipaddress import ip_address


DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

DNS_TOOLS = [
    "dig",
    "whois",
    "dnsrecon",
    "dnsenum",
    "fierce"
]

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?\b"
)

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

IPV6_CANDIDATE_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b"
)


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------


def dedupe_sorted(values):
    cleaned = []

    for value in values:
        if value is None:
            continue

        value = str(value).strip()

        if not value:
            continue

        cleaned.append(value)

    return sorted(set(cleaned))


def clean_dns_name(value):
    if not value:
        return ""

    return value.strip().strip('"').rstrip(".").lower()


def normalize_target(target):
    parsed = urlparse(target)

    if parsed.netloc:
        return parsed.netloc.strip().lower()

    return (
        target.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .strip()
        .lower()
    )


def derive_root_domain(domain):
    parts = domain.split(".")

    if len(parts) <= 2:
        return domain

    return ".".join(parts[-2:])


def is_valid_ip(value):
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_subdomain(domain, root_domain):
    domain = clean_dns_name(domain)

    if not domain:
        return False

    if domain == root_domain:
        return False

    if not domain.endswith("." + root_domain):
        return False

    if domain.startswith("0m"):
        return False

    labels = domain.split(".")

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def tool_exists(tool):
    return shutil.which(tool) is not None


def run_command(command, timeout=45, max_output=12000):
    tool = command[0]

    if not tool_exists(tool):
        return {
            "tool": tool,
            "status": "missing",
            "command": command,
            "stdout": "",
            "stderr": "",
            "returncode": None
        }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            "tool": tool,
            "status": "ok" if result.returncode == 0 else "error",
            "command": command,
            "stdout": result.stdout[:max_output],
            "stderr": result.stderr[:max_output],
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": tool,
            "status": "timeout",
            "command": command,
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": None
        }


# -----------------------------------------------------------------------------
# DNS collection
# -----------------------------------------------------------------------------


def run_dig(domain, record_type):
    result = run_command(
        ["dig", "+short", domain, record_type],
        timeout=20
    )

    values = [
        line.strip()
        for line in result.get("stdout", "").splitlines()
        if line.strip()
    ]

    return {
        "record_type": record_type,
        "values": values,
        "count": len(values),
        "tool_status": result["status"],
        "error": result["stderr"] if result["stderr"] else None
    }


def collect_dig_records(domain):
    return {
        record_type: run_dig(domain, record_type)
        for record_type in DNS_RECORD_TYPES
    }


def collect_dmarc(root_domain):
    dmarc_domain = f"_dmarc.{root_domain}"

    return {
        "domain": dmarc_domain,
        "records": collect_dig_records(dmarc_domain)
    }


def collect_basic_tool_outputs(domain, root_domain):
    return {
        "dig_target_any": run_command(["dig", domain, "ANY"], timeout=25),
        "dig_root_any": run_command(["dig", root_domain, "ANY"], timeout=25),

        "whois_root": run_command(["whois", root_domain], timeout=35),

        "dnsrecon_root": run_command(["dnsrecon", "-d", root_domain], timeout=90),
        "dnsenum_root": run_command(["dnsenum", root_domain], timeout=120),
        "fierce_root": run_command(["fierce", "--domain", root_domain], timeout=120)
    }


# -----------------------------------------------------------------------------
# Extraction helpers
# -----------------------------------------------------------------------------


def extract_txt_values(records):
    return records.get("TXT", {}).get("values", [])


def find_spf(txt_values):
    return [
        value
        for value in txt_values
        if "v=spf1" in value.lower()
    ]


def extract_domains_from_text(text, root_domain):
    if not text:
        return []

    domains = []

    for match in DOMAIN_PATTERN.findall(text):
        domain = clean_dns_name(match)

        if is_valid_subdomain(domain, root_domain) or domain == root_domain:
            domains.append(domain)

    return dedupe_sorted(domains)


def extract_ips_from_text(text):
    if not text:
        return []

    candidates = []

    candidates.extend(IPV4_PATTERN.findall(text))
    candidates.extend(IPV6_CANDIDATE_PATTERN.findall(text))

    valid_ips = [
        value
        for value in candidates
        if is_valid_ip(value)
    ]

    return dedupe_sorted(valid_ips)


def extract_discovered_subdomains(raw_tool_outputs, root_domain):
    discovered = set()

    discovery_tools = [
        "dnsrecon_root",
        "dnsenum_root",
        "fierce_root"
    ]

    for tool_name in discovery_tools:
        output = raw_tool_outputs.get(tool_name, {})

        combined_text = "\n".join([
            output.get("stdout", ""),
            output.get("stderr", "")
        ])

        for domain in extract_domains_from_text(combined_text, root_domain):
            if is_valid_subdomain(domain, root_domain):
                discovered.add(domain)

    return sorted(discovered)


def extract_nameserver_ips(raw_tool_outputs):
    ns_ips = set()

    for tool_name in ["dnsrecon_root", "dnsenum_root", "fierce_root"]:
        output = raw_tool_outputs.get(tool_name, {})

        combined_text = "\n".join([
            output.get("stdout", ""),
            output.get("stderr", "")
        ])

        for ip in extract_ips_from_text(combined_text):
            ns_ips.add(ip)

    return sorted(ns_ips)


# -----------------------------------------------------------------------------
# Normalized evidence
# -----------------------------------------------------------------------------


def build_normalized_records(domain, root_domain):
    target_records = collect_dig_records(domain)
    root_records = collect_dig_records(root_domain)
    dmarc = collect_dmarc(root_domain)

    root_txt = extract_txt_values(root_records)
    dmarc_txt = extract_txt_values(dmarc["records"])

    return {
        "target_domain": {
            "domain": domain,
            "records": target_records
        },
        "root_domain": {
            "domain": root_domain,
            "records": root_records
        },
        "mail_security": {
            "spf": {
                "present": bool(find_spf(root_txt)),
                "records": find_spf(root_txt)
            },
            "dmarc": {
                "domain": dmarc["domain"],
                "present": bool(dmarc_txt),
                "records": dmarc_txt
            },
            "dkim": {
                "present": None,
                "reason": "DKIM selectors were not provided and cannot be reliably inferred."
            }
        },
        "authority": {
            "target_ns": target_records.get("NS", {}).get("values", []),
            "root_ns": root_records.get("NS", {}).get("values", []),
            "root_soa": root_records.get("SOA", {}).get("values", []),
            "root_caa": root_records.get("CAA", {}).get("values", [])
        },
        "signals": {
            "target_has_ipv4": bool(target_records.get("A", {}).get("values")),
            "target_has_ipv6": bool(target_records.get("AAAA", {}).get("values")),
            "root_has_mx": bool(root_records.get("MX", {}).get("values")),
            "root_has_spf": bool(find_spf(root_txt)),
            "root_has_dmarc": bool(dmarc_txt),
            "root_has_caa": bool(root_records.get("CAA", {}).get("values"))
        }
    }


def build_deterministic_findings(normalized_records):
    findings = []
    signals = normalized_records.get("signals", {})

    target_records = normalized_records["target_domain"]["records"]
    root_records = normalized_records["root_domain"]["records"]

    ipv4_values = target_records.get("A", {}).get("values", [])
    ipv6_values = target_records.get("AAAA", {}).get("values", [])
    root_ns = root_records.get("NS", {}).get("values", [])

    if signals.get("target_has_ipv4"):
        findings.append(
            f"Target domain resolves to {len(ipv4_values)} IPv4 address(es)."
        )
    else:
        findings.append("No IPv4 records were observed for the target domain.")

    if signals.get("target_has_ipv6"):
        findings.append(
            f"Target domain resolves to {len(ipv6_values)} IPv6 address(es)."
        )
    else:
        findings.append("No IPv6 records were observed for the target domain.")

    if root_ns:
        findings.append("Root domain uses authoritative nameservers.")
    else:
        findings.append("No authoritative nameservers were observed for the root domain.")

    if signals.get("root_has_mx"):
        findings.append("MX records were observed for the root domain.")
    else:
        findings.append("No MX records were observed for the root domain.")

    if signals.get("root_has_spf"):
        findings.append("SPF record was observed for the root domain.")
    else:
        findings.append("No SPF record was observed for the root domain.")

    if signals.get("root_has_dmarc"):
        findings.append("DMARC record was observed for the root domain.")
    else:
        findings.append("No DMARC record was observed for the root domain.")

    if signals.get("root_has_caa"):
        findings.append("CAA records were observed for the root domain.")
    else:
        findings.append("No CAA records were observed for the root domain.")

    return findings


def build_confirmed_assets(normalized_records, discovered_subdomains=None, nameserver_ips=None):
    assets = set()

    discovered_subdomains = discovered_subdomains or []
    nameserver_ips = nameserver_ips or []

    target = normalized_records["target_domain"]
    root = normalized_records["root_domain"]
    root_domain = root["domain"]

    assets.add(target["domain"])
    assets.add(root_domain)

    for record in ["A", "AAAA", "CNAME"]:
        for value in target["records"].get(record, {}).get("values", []):
            if record == "CNAME":
                assets.add(clean_dns_name(value))
            elif is_valid_ip(value):
                assets.add(value)

    for record in ["A", "AAAA", "NS", "MX", "CNAME"]:
        for value in root["records"].get(record, {}).get("values", []):
            if record in ["NS", "CNAME"]:
                assets.add(clean_dns_name(value))
            elif record == "MX":
                parts = value.split()
                mx_host = clean_dns_name(parts[-1]) if parts else ""
                if mx_host:
                    assets.add(mx_host)
            elif is_valid_ip(value):
                assets.add(value)

    dmarc_domain = normalized_records["mail_security"]["dmarc"]["domain"]

    if normalized_records["mail_security"]["dmarc"]["present"]:
        assets.add(dmarc_domain)

    for subdomain in discovered_subdomains:
        subdomain = clean_dns_name(subdomain)
        if is_valid_subdomain(subdomain, root_domain):
            assets.add(subdomain)

    for ip in nameserver_ips:
        if is_valid_ip(ip):
            assets.add(ip)

    return sorted(assets)


def build_next_collection_targets(domain, root_domain, discovered_subdomains, confirmed_assets):
    targets = set()

    targets.add(domain)
    targets.add(root_domain)

    for subdomain in discovered_subdomains:
        subdomain = clean_dns_name(subdomain)

        if is_valid_subdomain(subdomain, root_domain):
            targets.add(subdomain)

    for asset in confirmed_assets:
        cleaned = clean_dns_name(asset)

        if cleaned == root_domain:
            targets.add(cleaned)

        elif is_valid_subdomain(cleaned, root_domain):
            targets.add(cleaned)

    return sorted(targets)


def collect_tool_status(raw_tool_outputs):
    return {
        name: output.get("status")
        for name, output in raw_tool_outputs.items()
    }


#def identify_provider_candidates(normalized_records, raw_tool_outputs):
#    candidates = set()
#
#    root_ns = normalized_records.get("authority", {}).get("root_ns", [])
#    soa = normalized_records.get("authority", {}).get("root_soa", [])
#
#    combined = " ".join(root_ns + soa).lower()
#
#    if "cloudflare.com" in combined:
#        candidates.add("Cloudflare")
#
#    if "awsdns" in combined or "amazonaws" in combined:
#        candidates.add("Amazon Web Services")
#
#    if "azure-dns" in combined:
#        candidates.add("Microsoft Azure")
#
#    if "googledomains" in combined or "google.com" in combined:
#        candidates.add("Google")
#
#    whois_text = raw_tool_outputs.get("whois_root", {}).get("stdout", "").lower()
#
#    if "godaddy" in whois_text:
#        candidates.add("GoDaddy")
#
#    return sorted(candidates)
#

def build_provider_indicators(normalized_records, raw_tool_outputs):
    return {
        "nameservers": normalized_records.get("authority", {}).get("root_ns", []),
        "soa": normalized_records.get("authority", {}).get("root_soa", []),
        "whois_excerpt": raw_tool_outputs.get("whois_root", {}).get("stdout", "")[:2000]
    }


def build_unknowns(normalized_records):
    unknowns = []

    if normalized_records["mail_security"]["dkim"]["present"] is None:
        unknowns.append("DKIM selectors were not provided and cannot be reliably inferred.")

    return unknowns


def build_rabbit_evidence(evidence):
    return {
        "target": evidence["target"],
        "domain": evidence["domain"],
        "root_domain": evidence["root_domain"],
        "deterministic_findings": evidence["deterministic_findings"],
        "confirmed_assets": evidence["confirmed_assets"],
        "discovered_subdomains": evidence["discovered_subdomains"],
        "nameserver_ips": evidence["nameserver_ips"],
        "next_collection_targets": evidence["next_collection_targets"],
        #"identified_provider_candidates": evidence["identified_provider_candidates"],
        "provider_indicators": evidence["provider_indicators"],
        "unknowns_seed": evidence["unknowns_seed"],
        "signals": evidence["normalized_records"]["signals"]
    }


# -----------------------------------------------------------------------------
# Collector entry point
# -----------------------------------------------------------------------------


def collect_dns_evidence(target):
    domain = normalize_target(target)
    root_domain = derive_root_domain(domain)

    normalized_records = build_normalized_records(domain, root_domain)
    raw_tool_outputs = collect_basic_tool_outputs(domain, root_domain)

    discovered_subdomains = extract_discovered_subdomains(
        raw_tool_outputs,
        root_domain
    )

    nameserver_ips = extract_nameserver_ips(raw_tool_outputs)

    deterministic_findings = build_deterministic_findings(normalized_records)

    confirmed_assets = build_confirmed_assets(
        normalized_records,
        discovered_subdomains=discovered_subdomains,
        nameserver_ips=nameserver_ips
    )

    next_collection_targets = build_next_collection_targets(
        domain,
        root_domain,
        discovered_subdomains,
        confirmed_assets
    )

    evidence = {
        "collector": "dns",
        "target": target,
        "domain": domain,
        "root_domain": root_domain,
        "tools_requested": DNS_TOOLS,
        "tool_status": collect_tool_status(raw_tool_outputs),
        "normalized_records": normalized_records,
        "deterministic_findings": deterministic_findings,
        "confirmed_assets": confirmed_assets,
        "discovered_subdomains": discovered_subdomains,
        "nameserver_ips": nameserver_ips,
        "next_collection_targets": next_collection_targets,
        #"identified_provider_candidates": identify_provider_candidates(
         #   normalized_records,
          #  raw_tool_outputs
        #),
        "provider_indicators": build_provider_indicators(
            normalized_records,
            raw_tool_outputs
        ),
        "unknowns_seed": build_unknowns(normalized_records),
        "rabbit_evidence": None,
        "raw_tool_outputs": raw_tool_outputs
    }

    evidence["rabbit_evidence"] = build_rabbit_evidence(evidence)

    return evidence


# -----------------------------------------------------------------------------
# Rabbit prompts owned by DNS domain
# -----------------------------------------------------------------------------


def build_dns_planning_prompt(target, mode):
    return f"""
Respond ONLY with valid JSON.

You are WhiteRabbit Neo, a cybersecurity specialist used by MagnoCyber.

Target: {target}
Mode: {mode}
Domain: dns

Focus only on DNS reconnaissance.

Rules:
- Never claim to have accessed the target before evidence is collected.
- Never invent technologies, vulnerabilities, users, business context, firewall, WAF, or OS.
- Recon mode must focus on evidence collection.
- Do not recommend mitigations.
- Do not use markdown.
- Do not add extra text.

Return exactly this JSON structure:

{{
  "target": "{target}",
  "mode": "{mode}",
  "domain": "dns",
  "objective": "Collect DNS evidence for name resolution, authority, mail security, and DNS discovery.",
  "known_facts": [
    "The operator provided the target: {target}",
    "The operator selected mode: {mode}",
    "The operator selected domain: dns"
  ],
  "unknowns": [
    "Target DNS records",
    "Root DNS records",
    "Authoritative nameservers",
    "Mail security records",
    "Subdomain discovery results"
  ],
  "recommended_collection": [
    "Collect DNS records for the target domain",
    "Collect DNS records for the root domain",
    "Collect MX, SPF, DMARC, SOA, NS, TXT, CAA, A, AAAA, and CNAME records",
    "Run DNS discovery tools against the root domain",
    "Normalize collected evidence"
  ],
  "confidence": "medium"
}}
""".strip()


def build_dns_analysis_prompt(target, mode, evidence):
    rabbit_evidence = evidence.get("rabbit_evidence", evidence)

    evidence_json = json.dumps(
        rabbit_evidence,
        indent=2,
        ensure_ascii=False
    )

    return f"""
Respond ONLY with valid JSON.

You are WhiteRabbit Neo, a cybersecurity specialist used by MagnoCyber.

Target: {target}
Mode: {mode}
Domain: dns

Collected DNS evidence:

{evidence_json}

Rules:
- Use only the collected DNS evidence.
- Do not invent assets, technologies, vulnerabilities, users, business context, firewall, WAF, or OS.
- Do not recommend mitigations.
- Do not explain what DNS is.
- Do not use markdown.
- Do not add extra text.
- observations must copy deterministic_findings exactly.
- confirmed_assets must copy confirmed_assets exactly.
- next_collection_targets must copy next_collection_targets exactly.
#- identified_technologies may use only provider_candidates.
- identified_technologies must contain provider or technology names inferred from explicit provider evidence observed in NS, SOA, or WHOIS evidence; do not use evidence source names such as NS, SOA, WHOIS, or Nameservers as technologies.
- unknowns may use only unknowns_seed or explicit missing evidence.
- confidence must be one of: low, medium, high.

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


# -----------------------------------------------------------------------------
# Optional CLI execution
# -----------------------------------------------------------------------------


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 dns_collector.py <target>")
        sys.exit(1)

    result = collect_dns_evidence(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))








