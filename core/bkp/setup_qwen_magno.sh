#!/usr/bin/env bash
set -euo pipefail

# Magno Cyber - Qwen local setup through Ollama
# Tested workflow target: Linux/Kali/Ubuntu-like systems.

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama was not found. Install it first from the official Ollama package for your OS."
  echo "Linux quick install usually is: curl -fsSL https://ollama.com/install.sh | sh"
  exit 1
fi

ollama pull qwen3:8b

echo "Qwen is ready. Test with: ollama run qwen3:8b"
echo "Run Magno web collector example:"
echo "python3 web_collector.py https://example.com --profile standard --i-have-authorization"
