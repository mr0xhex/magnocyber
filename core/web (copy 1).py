#!/usr/bin/python3

import os
import json
import requests
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# CONFIGURAÇÕES DE DIRETÓRIOS E MODELOS
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_ANALYST = "Qwen3:8b"
MODEL_WRITER = "llama3.1:8b"

PROMPT_PATH = os.path.join("/opt","work","magno", "prompts", "llm_security_audit.txt")
NUCLEI_OUTPUT_PATH = os.path.join("/opt","work","magno","reports", "output.json") # O arquivo gerado pelo seu comando do Nuclei

# TIMESTAMP PARA ARQUIVOS
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

def load_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def save_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def call_ollama(model, system_prompt, user_data, force_json=False):
    """Chama a API do Ollama e descarrega o modelo imediatamente após o uso (keep_alive=0)"""
    print(f"[*] Executando análise com o modelo: {model}...")

    prompt_final = f"{system_prompt}\n\n[DATA TO ANALYZE]:\n{user_data}"

    payload = {
        "model": model,
        "prompt": prompt_final,
        "stream": False,
        "options": {
            "keep_alive": 0  # Descarrega o modelo da memória (RAM/VRAM) logo após responder
        }
    }

    if force_json:
        payload["format"] = "json"

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "")
    except Exception as e:
        print(f"[!] Erro ao chamar o Ollama ({model}): {e}")
        return None

def generate_pdf_report(json_data, output_pdf_name):
    """Gera um PDF colorido e estruturado a partir do JSON gerado pela Qwen"""
    print(f"[*] Construindo o PDF relatório: {output_pdf_name}...")
    doc = SimpleDocTemplate(output_pdf_name, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()

    # Custom Styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor("#1A365D"), spaceAfter=12)
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#2B6CB0"), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('BodyStyle', parent=styles['BodyText'], fontSize=10, leading=14, textColor=colors.HexColor("#2D3748"))

    # Capa / Título Principal
    story.append(Paragraph("Security Audit & Risk Assessment Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 15))

    # Resumo Executivo
    summary = json_data.get("executive_summary", {})
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(f"<b>Overall System Risk Level:</b> {summary.get('overall_system_risk', 'N/A')}", body_style))
    story.append(Paragraph(f"• Critical Vulnerabilities: {summary.get('total_critical_vulnerabilities', 0)}", body_style))
    story.append(Paragraph(f"• High Vulnerabilities: {summary.get('total_high_vulnerabilities', 0)}", body_style))
    story.append(Paragraph(f"• Medium Vulnerabilities: {summary.get('total_medium_vulnerabilities', 0)}", body_style))
    story.append(Spacer(1, 15))

    # Tabela de Vulnerabilidades Encontradas
    story.append(Paragraph("2. Detailed Findings", h2_style))

    vulns = json_data.get("detected_vulnerabilities", [])
    for idx, vuln in enumerate(vulns, start=1):
        story.append(Paragraph(f"<b>Finding #{idx}: {vuln.get('category', 'General')}</b>", body_style))

        # Colorir a severidade dinamicamente
        sev = vuln.get('severity', 'Low').upper()
        sev_color = "#E53E3E" if "CRIT" in sev or "HIGH" in sev else "#DD6B20"

        data = [
            [Paragraph(f"<b>Affected URL:</b> {vuln.get('affected_url')}", body_style)],
            [Paragraph(f"<b>Severity:</b> <font color='{sev_color}'><b>{sev}</b></font> | <b>CVE:</b> {vuln.get('associated_cve', 'None')}", body_style)],
            [Paragraph(f"<b>Description:</b> {vuln.get('finding_description')}", body_style)],
            [Paragraph(f"<b>Potential Impact:</b> {vuln.get('potential_impact')}", body_style)],
            [Paragraph(f"<b>Remediation:</b> {vuln.get('remediation_recommendation')}", body_style)],
        ]

        t = Table(data, colWidths=[530])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F7FAFC")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#E2E8F0")),
            ('PADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,-1), (-1,-1), 8),
        ]))

        story.append(t)
        story.append(Spacer(1, 12))

    doc.build(story)
    print(f"[+] Relatório PDF gerado com sucesso!")

def main():
    # 1. Carrega os arquivos necessários
    print("[*] Iniciando o processamento do Framework...")
    if not os.path.exists(PROMPT_PATH) or not os.path.exists(NUCLEI_OUTPUT_PATH):
        print("[!] Arquivos de entrada necessários não foram encontrados. Verifique os caminhos.")
        return

    system_prompt = load_file(PROMPT_PATH)
    nuclei_raw_data = load_file(NUCLEI_OUTPUT_PATH)

    # 2. Roda a Qwen3:8b para estruturar o JSON bruto do Nuclei
    qwen_output = call_ollama(MODEL_ANALYST, system_prompt, nuclei_raw_data, force_json=True)

    if not qwen_output:
        print("[!] Falha na geração do JSON analítico.")
        return

    # Salva o JSON estruturado gerado pela Qwen
    qwen_json_name = f"qwen_analysis_{timestamp}.json"
    save_file(qwen_json_name, qwen_output)
    print(f"[+] Análise estruturada salva em: {qwen_json_name}")

    # Converte a string de resposta da Qwen em um dicionário Python válido
    try:
        parsed_json_data = json.loads(qwen_output)
    except json.JSONDecodeError:
        print("[!] Erro: A saída da Qwen não retornou um JSON perfeitamente válido.")
        return

    # 3. Transforma a análise técnica em texto refinado/PDF usando o llama3.1:8b
    # Criamos um prompt temporário focado em redação executiva e design para guiar o Llama3.1
    writer_prompt = (
        "You are an expert technical writer. Take the following audited JSON data and translate any "
        "raw technical terms into an executive summary. Provide clear descriptions for the report."
    )

    # Chamamos o Llama3.1 passando o JSON estruturado pela Qwen
    llama_output = call_ollama(MODEL_WRITER, writer_prompt, json.dumps(parsed_json_data, indent=2))

    if llama_output:
        llama_text_name = f"llama_report_{timestamp}.txt"
        save_file(llama_text_name, llama_output)
        print(f"[+] Resumo textual do Llama salvo em: {llama_text_name}")

    # 4. Gera o PDF Executivo Final com os dados consolidados
    pdf_report_name = f"Executive_Security_Report_{timestamp}.pdf"
    generate_pdf_report(parsed_json_data, pdf_report_name)

    print("[+] Fluxo do domínio concluído perfeitamente.")

if __name__ == "__main__":
    main()

