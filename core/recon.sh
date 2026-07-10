#!/bin/bash

# ==============================================================================
# CONFIGURATIONS - ADJUST YOUR TARGET HERE
# ==============================================================================
DOMINIO="alwaysoncyber.com" # <-- Mude aqui para o seu domínio principal


TIMESTAMP=$(date +"%Y%m%d_%H%M")
BASE_DIR="/opt/work/magno"
REPORTS_DIR="$BASE_DIR/reports"
SUBDOMAINS_FILE="$BASE_DIR/subdomains.txt"

# Standardized output paths for the Python framework
NUCLEI_OUT="$REPORTS_DIR/output_nuclei-$TIMESTAMP.json"
KATANA_OUT="$REPORTS_DIR/output_katana-$TIMESTAMP.json"
FEROX_OUT="$REPORTS_DIR/output_ferox-$TIMESTAMP.json"

# Colors for terminal output formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Starting Automated Recon Pipeline for: ${DOMINIO}${NC}"

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

# Clean up previous scan files to prevent old data pollution
echo -e "${YELLOW}[*] Cleaning up old inputs...${NC}"
rm -f "$SUBDOMAINS_FILE" "$NUCLEI_OUT" "$KATANA_OUT" "$FEROX_OUT"

# ==============================================================================
# PHASE 1: SUBDOMAIN DISCOVERY (Subfinder)
# ==============================================================================
echo -e "${GREEN}[+] Running Subfinder to map infrastructure...${NC}"
subfinder -d "$DOMINIO" -o "$SUBDOMAINS_FILE"

# Quick check if subdomains were found
if [ ! -s "$SUBDOMAINS_FILE" ]; then
    echo -e "${YELLOW}[!] Subfinder did not find subdomains. Using root domain as fallback.${NC}"
    echo "$DOMINIO" > "$SUBDOMAINS_FILE"
fi

# ==============================================================================
# PHASE 2: VULNERABILITY & TLS SCANNING (Nuclei)
# ==============================================================================
echo -e "${GREEN}[+] Running Nuclei (Vulnerabilities, Certificates & TLS)...${NC}"
nuclei -l "$SUBDOMAINS_FILE" -json-export "$NUCLEI_OUT"

# ==============================================================================
# PHASE 3: WEB CRAWLING & ENDPOINT DISCOVERY (Katana)
# ==============================================================================
echo -e "${GREEN}[+] Running Katana Crawler to find hidden parameters and endpoints...${NC}"
katana -u "$SUBDOMAINS_FILE" -json-export "$KATANA_OUT"

# ==============================================================================
# PHASE 4: DIRECTORY BRUTE FORCE (Feroxbuster)
# ==============================================================================
echo -e "${GREEN}[+] Running Feroxbuster for sensitive files discovery...${NC}"
# Feroxbuster works better scanning targets individually or reading from a list via stdin
cat "$SUBDOMAINS_FILE" | feroxbuster --stdin -o "$FEROX_OUT"

# ==============================================================================
# PHASE 5: TRIGGER LLM REASONING FRAMEWORK
# ==============================================================================
echo -e "${BLUE}[*] Recon pipeline completed successfully!${NC}"
echo -e "${YELLOW}[*] Triggering Python LLM Framework to process telemetry logs...${NC}"

if [ -f "$BASE_DIR/core/web.py" ]; then
    python3 "$BASE_DIR/core/web.py"
else
    echo -e "[!] Python script not found at $BASE_DIR/core/web.py. Please run it manually."
fi

echo -e "${GREEN}[+] All tasks completed flawlessly! Check your PDF in /reports.${NC}"
