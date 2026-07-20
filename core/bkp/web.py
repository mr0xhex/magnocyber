#!/usr/bin/python3

import os
import sys
import json
import requests
import argparse
import subprocess
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# DIRECTORY AND MODEL CONFIGURATIONS
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_ANALYST = "Qwen2.5:14b"
MODEL_WRITER = "llama3.1:8b"

# Gera o timestamp no formato exato: Ex: 10Jul26-1002
timestamp_pasta = datetime.now().strftime("%d%b%y-%H%M")

BASE_DIR = "/opt/work/magno/"
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")
PROMPT_PATH = os.path.join(PROMPTS_DIR, "llm_security_audit.txt")

def extract_clean_host(domain):
    """
    Extracts a clean folder name from the domain.
    e.g., 'sub.target.com.br' -> 'target' or 'example.com' -> 'example'
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        if "com" in parts[-2] or "net" in parts[-2]:
            return parts[-3] if len(parts) >= 3 else parts[0]
        return parts[-2]
    return domain

def run_command(command_list, description):
    """Safely executes a system binary via subprocess."""
    print(f"\n[+] Launching subprocess: {description}...")
    try:
        subprocess.run(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing {description}: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[!] Binary mismatch error. Is the tool installed in your PATH?")
        return False


def run_recon_pipeline(target_domain, target_reports_dir, subdomains_file, nuclei_path, katana_path, ferox_path):
    """Orchestrates and executes all command line scanning tools natively from Python."""
    print(f"[*] Initializing Recon Automation Pipeline for Target: {target_domain}")
    print(f"[*] Workspace Directory created at: {target_reports_dir}")
    os.makedirs(target_reports_dir, exist_ok=True)

    # 1. Ajuste do Alvo (Garante formato de URL básico caso seja apenas um IP)
    target_url = target_domain
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"http://{target_domain}"

    # 2. Nuclei Execution (Varredura de Vulnerabilidades Direta no Alvo)
    run_command(
        ["nuclei", "-u", target_url, "-json-export", nuclei_path],
        "Vulnerability Scan (Nuclei)"
    )

    # 3. Katana Execution (Web Crawling em JSON Avançado)
    run_command(
        ["katana", "-u", target_url, "-jc", "-o", katana_path],
        "Web Crawling (Katana)"
    )

    # 4. Feroxbuster Execution (Mapeamento de Diretórios sem depender de stdin)
    run_command(
        ["feroxbuster", "-u", target_url, "-o", ferox_path, "--silent"],
        "Directory Brute Force (Feroxbuster)"
    )



def load_file(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def save_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def carregar_diretorio_individual_em_memoria(target_reports_dir):
    """
    PROPOSTA NOVA: Varre o diretorio de relatorios e carrega cada arquivo 
    INDIVIDUALMENTE na memoria RAM estruturando um JSON dinamico para a IA.
    Nao gera arquivo master intermediario no disco.
    """
    print(f"[*] Módulo RAM: Carregando arquivos individualmente de: {target_reports_dir}")
    
    payload_memoria = {
        "framework_metadata": {
            "engine": "Dynamic-Memory-Loader-v3",
            "organization": "ALWAYSONCYBER",
            "operator": "Magno",
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "target_telemetry_files": {}
    }

    # Varre a pasta de forma totalmente cega e dinâmica
    for arquivo_nome in os.listdir(target_reports_dir):
        caminho_completo = os.path.join(target_reports_dir, arquivo_nome)
        
        # Pula diretórios ou arquivos gerados pelas execuções antigas de IA para evitar loop
        if os.path.isdir(caminho_completo) or "qwen_analysis" in arquivo_nome or "llama_report" in arquivo_nome or "Executive" in arquivo_nome:
            continue
            
        print(f"[+] Carregando em memória RAM individualmente -> {arquivo_nome}")
        try:
            with open(caminho_completo, 'r', encoding='utf-8') as f:
                conteudo = f.read().strip()
                
                # Se o arquivo for JSON ou JSON Lines (Nuclei / Katana)
                if arquivo_nome.endswith('.json'):
                    try:
                        # Tenta dar parse como JSON puro padrão
                        payload_memoria["target_telemetry_files"][arquivo_nome] = json.loads(conteudo)
                    except json.JSONDecodeError:
                        # Se falhar, trata como JSON Lines (linha por linha independente)
                        linhas_estruturadas = []
                        for linha in conteudo.split('\n'):
                            if linha.strip():
                                try:
                                    linhas_estruturadas.append(json.loads(linha.strip()))
                                except:
                                    linhas_estruturadas.append({"raw_line": linha.strip()})
                        payload_memoria["target_telemetry_files"][arquivo_nome] = linhas_estruturadas
                else:
                    # Se for arquivo TXT (Subfinder / Ferox), joga as linhas limpas num array limpo
                    linhas_txt = [l.strip() for l in conteudo.split('\n') if l.strip()]
                    payload_memoria["target_telemetry_files"][arquivo_nome] = linhas_txt
                    
        except Exception as e:
            print(f"[!] Erro ao carregar o arquivo {arquivo_nome} em memória: {e}")

    return payload_memoria

def call_ollama(model, system_prompt, user_data, force_json=False):
    print(f"[*] Running automated analysis with model: {model}...")
    prompt_final = f"{system_prompt}\n\n[DATA TO ANALYZE]:\n{user_data}"

    payload = {
        "model": model,
        "prompt": prompt_final,
        "stream": False,
        "options": {
            "keep_alive": 0,
            "num_ctx": 32768  
        }
     } 
    if force_json:
        payload["format"] = "json"

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "")
    except Exception as e:
        print(f"[!] Error invoking Ollama ({model}): {e}")
        return None



def generate_pdf_report(target_domain, json_data, output_pdf_name):
    """
    Renderizador Ultra-Tolerante e Inteligente: Se a IA falhar em estruturar os arrays
    ou esconder dados em blocos textuais (como chaves 'body' ou textões), o script
    faz uma varredura recursiva para extrair logs informacionais e impedir relatórios zerados.
    """
    print(f"[*] Building executive PDF report document: {output_pdf_name}...")
    doc = SimpleDocTemplate(output_pdf_name, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=22, textColor=colors.HexColor("#1A365D"), spaceAfter=12)
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#2B6CB0"), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle('BodyStyle', parent=styles['BodyText'], fontSize=10, leading=14, textColor=colors.HexColor("#2D3748"))
    table_cell_style = ParagraphStyle('TableCellStyle', parent=styles['BodyText'], fontSize=9, leading=12, textColor=colors.HexColor("#2D3748"))

    story.append(Paragraph(f"Security Audit Report: {target_domain}", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 15))

    # ---- PARSE GERAL DE VULNERABILIDADES ----
    vulns_list = []
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    info_count = 0

    # Tenta obter as fontes estruturadas padrão
    v_source = json_data.get("detected_vulnerabilities", json_data.get("vulnerabilities", json_data.get("findings", [])))
    
    if not v_source and "matched_templates" in json_data:
        v_source = json_data.get("matched_templates", [])
    elif not v_source and "nuclei_template_id" in json_data:
        templates = json_data.get("nuclei_template_id", [])
        urls = json_data.get("matched_at", [target_domain])
        for idx, t_id in enumerate(templates):
            v_source.append({
                "category": t_id,
                "affected_url": urls[idx] if idx < len(urls) else urls[0],
                "severity": "info",
                "finding_description": f"Identificado template ativo do Nuclei: {t_id}"
            })

    # FALLBACK DE EMERGÊNCIA: Se a IA colocou os dados textuais soltos na raiz ou em chaves como 'body'
    if not v_source or len(v_source) == 0:
        def extract_info_fallbacks(data):
            extracted = []
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in ["body", "response", "output", "analysis", "text", "description"] and isinstance(v, str) and len(v.strip()) > 20:
                        # Quebra blocos de texto grandes em parágrafos ou linhas significativas
                        linhas = [l.strip() for l in v.split('\n') if len(l.strip()) > 15]
                        for linha in linhas:
                            extracted.append({
                                "category": f"Telemetry Log Analisado ({k.upper()})",
                                "finding_description": linha,
                                "severity": "INFO"
                            })
                    else:
                        extracted.extend(extract_info_fallbacks(v))
            elif isinstance(data, list):
                for item in data:
                    extracted.extend(extract_info_fallbacks(item))
            return extracted

        v_source = extract_info_fallbacks(json_data)

    # Normaliza e higieniza os achados capturados
    for idx, item in enumerate(v_source):
        if isinstance(item, str):
            item = {
                "category": "Log de Telemetria Identificado",
                "finding_description": item,
                "severity": "HIGH" if "high" in item.lower() or "crit" in item.lower() else ("MEDIUM" if "med" in item.lower() else "INFO")
            }

        if not isinstance(item, dict):
            continue

        raw_sev = item.get("severity", "info")
        if isinstance(raw_sev, dict):
            raw_sev = raw_sev.get("severity", "info")
        if not raw_sev and "info" in item and isinstance(item["info"], dict):
            raw_sev = item["info"].get("severity", "info")
            
        severity = str(raw_sev or "info").upper()
        
        # Contabiliza os contadores reais
        if "CRIT" in severity: crit_count += 1
        elif "HIGH" in severity: high_count += 1
        elif "MED" in severity: med_count += 1
        elif "LOW" in severity: low_count += 1
        else: info_count += 1

        info_dict = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        classification_dict = info_dict.get("classification", {}) if isinstance(info_dict.get("classification"), dict) else {}

        # Escapa caracteres ou valores ausentes para o ReportLab não quebrar
        vulns_list.append({
            "category": str(item.get("category", item.get("template_id", item.get("name", "Informação de Auditoria")))),
            "url": str(item.get("affected_url", item.get("matched_at", item.get("url", target_domain)))),
            "severity": severity,
            "cve": str(item.get("associated_cve", item.get("cve", classification_dict.get("cve-id", "None")))),
            "description": str(item.get("finding_description", item.get("description", info_dict.get("description", "Log ou telemetria capturada nos analisadores locais.")))),
            "impact": str(item.get("potential_impact", item.get("impact", "Exposição de informações de infraestrutura / Metadados ativos."))),
            "remediation": str(item.get("remediation_recommendation", item.get("remediation", item.get("fix", "Verificar necessidade de exposição pública deste cabeçalho ou serviço conforme a política de hardening."))))
        })

    # ---- 1. EXECUTIVE SUMMARY ----
    summary = json_data.get("executive_summary", json_data.get("summary", {}))
    if not isinstance(summary, dict):
        summary = {}
        
    risk_level = summary.get("overall_system_risk", summary.get("risk_level", ""))
    if not risk_level:
        if crit_count > 0 or high_count > 0: risk_level = "HIGH / CRITICAL"
        elif med_count > 0: risk_level = "MEDIUM"
        else: risk_level = "LOW / INFORMATIONAL"

    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(f"<b>Overall System Risk Level:</b> {risk_level}", body_style))
    story.append(Paragraph(f"• Critical Vulnerabilities: {crit_count}", body_style))
    story.append(Paragraph(f"• High Vulnerabilities: {high_count}", body_style))
    story.append(Paragraph(f"• Medium Vulnerabilities: {med_count}", body_style))
    story.append(Paragraph(f"• Low Vulnerabilities: {low_count}", body_style))
    story.append(Paragraph(f"• Informational Logs: {info_count}", body_style))
    story.append(Spacer(1, 15))

    # ---- 2. DETAILED FINDINGS ----
    story.append(Paragraph("2. Detailed Findings", h2_style))
    
    if not vulns_list:
        story.append(Paragraph("<i>No specific vulnerability findings were parsed from the telemetry data.</i>", body_style))

    for idx, v in enumerate(vulns_list, start=1):
        story.append(Paragraph(f"<b>Finding #{idx}: {v['category']}</b>", body_style))
        
        sev_color = "#E53E3E" if "CRIT" in v['severity'] or "HIGH" in v['severity'] else ("#DD6B20" if "MED" in v['severity'] else "#3182CE")

        data = [
            [Paragraph(f"<b>Affected URL:</b> {v['url']}", table_cell_style)],
            [Paragraph(f"<b>Severity:</b> <font color='{sev_color}'><b>{v['severity']}</b></font> | <b>CVE:</b> {v['cve']}", table_cell_style)],
            [Paragraph(f"<b>Description:</b> {v['description']}", table_cell_style)],
            [Paragraph(f"<b>Potential Impact:</b> {v['impact']}", table_cell_style)],
            [Paragraph(f"<b>Remediation:</b> {v['remediation']}", table_cell_style)],
        ]
        
        t = Table(data, colWidths=[530])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F7FAFC")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#E2E8F0")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,-1), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

    doc.build(story)
    print(f"[+] Executive PDF Report compiled successfully!")


def main():
    parser = argparse.ArgumentParser(description="Integrated Security Framework Engine CLI")
    parser.add_argument("--target", required=True, help="Target domain to perform the security audit (e.g., example.com)")
    args = parser.parse_args()

    target_domain = args.target
    clean_host = extract_clean_host(target_domain)
    
    folder_name = f"{clean_host}-{timestamp_pasta}"
    target_reports_dir = os.path.join(BASE_DIR, "reports", folder_name)
    
    subdomains_file = os.path.join(target_reports_dir, "output_subdomain.txt")
    nuclei_path = os.path.join(target_reports_dir, "output_nuclei.json")
    ferox_path = os.path.join(target_reports_dir, "output_ferox.json")
    katana_path = os.path.join(target_reports_dir, "output_katana.json")

    print("[*] Launching Integrated Security Framework Engine...")
    
    if not os.path.exists(PROMPT_PATH):
        print(f"[!] Target Core Prompt System configuration missing at: {PROMPT_PATH}")
        return

    # STEP 1: EXECUTE PIPELINE WITH CURRENT TARGET PARAMETERS
    run_recon_pipeline(target_domain, target_reports_dir, subdomains_file, nuclei_path, katana_path, ferox_path)

    # STEP 2: CONSOLIDATE DATA DIRECTLY IN RAM (Abordagem Modular e Inteligente)
    recon_master_payload = carregar_diretorio_individual_em_memoria(target_reports_dir)
    
    # Opcional: Salvamos uma cópia desse JSON estruturado da RAM apenas para auditoria humana se necessário
    debug_json_path = os.path.join(target_reports_dir, f"audit_memory_payload_{timestamp_pasta}.json")
    with open(debug_json_path, "w", encoding="utf-8") as f:
        json.dump(recon_master_payload, f, indent=4, ensure_ascii=False)

    system_prompt = load_file(PROMPT_PATH)
    ai_raw_input_string = json.dumps(recon_master_payload, indent=2, ensure_ascii=False)

    # STEP 3: OLLAMA INTERACTION (QWEN)
    qwen_output = call_ollama(MODEL_ANALYST, system_prompt, ai_raw_input_string, force_json=True)
    if not qwen_output:
        print("[!] Analytical framework processing failed at stage 1.")
        return

    qwen_json_report_path = os.path.join(target_reports_dir, f"qwen_analysis_{timestamp_pasta}.json")
    save_file(qwen_json_report_path, qwen_output)

    try:
        parsed_json_data = json.loads(qwen_output)
    except json.JSONDecodeError:
        print("[!] Critical Failure: Qwen output violated structured JSON schema syntax rules.")
        return

    # STEP 4: OLLAMA INTERACTION (LLAMA3.1)
    writer_prompt = (
        "You are an expert technical writer. Take the following audited JSON data and translate any "
        "raw technical terms into an executive summary. Provide clear descriptions for the report."
    )
    llama_output = call_ollama(MODEL_WRITER, writer_prompt, json.dumps(parsed_json_data, indent=2))

    if llama_output:
        llama_text_report_path = os.path.join(target_reports_dir, f"llama_report_{timestamp_pasta}.txt")
        save_file(llama_text_report_path, llama_output)

    # STEP 5: PDF RENDER
    pdf_report_path = os.path.join(target_reports_dir, f"Executive_Security_Report_{timestamp_pasta}.pdf")
    generate_pdf_report(target_domain, parsed_json_data, pdf_report_path)

    print(f"\n[+] Entire automation workflow completed flawlessly for host: {clean_host.upper()}!")

if __name__ == "__main__":
    main()

