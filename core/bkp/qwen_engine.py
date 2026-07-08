#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

def extract_json_object(text: str) -> dict:
    if not text:
        raise ValueError("Qwen returned an empty response")

    text = text.strip()

    # Remove Qwen thinking blocks
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Remove markdown code fences
    text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"```$", "", text).strip()

    # Try direct JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Extract first JSON object
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"Qwen did not return a JSON object. Raw response starts with: {text[:300]}")

    candidate = text[start:end + 1]

    try:
        return json.loads(candidate)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON returned by Qwen: {e}. Raw candidate starts with: {candidate[:300]}")

def call_ollama(prompt: str, config: Dict[str, Any]) -> str:
    ai_cfg = config.get("ai", {})
    model = ai_cfg.get("model", "qwen3:8b")
    ollama_url = ai_cfg.get("ollama_url", "http://127.0.0.1:11434/api/generate")
    temperature = ai_cfg.get("temperature", 0.1)
    num_ctx = ai_cfg.get("num_ctx", 32768)

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": num_ctx,
        },
    }

    request = urllib.request.Request(
        ollama_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=900) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body.get("response", "")
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not connect to Ollama at {ollama_url}. Check if Ollama is running and the model is pulled."
        ) from exc


def analyze_evidence(prompt_file: str, evidence_file: str, output_file: str, config: Dict[str, Any]) -> str:
    instructions = Path(prompt_file).read_text(encoding="utf-8")
    evidence = Path(evidence_file).read_text(encoding="utf-8", errors="replace")

    full_prompt = f"""
{instructions}

RAW EVIDENCE START
{evidence}
RAW EVIDENCE END
""".strip()

    response = call_ollama(full_prompt, config)
    debug_file = output_file.replace("_findings.json", "_qwen_raw_response.txt")

    with open(debug_file, "w", encoding="utf-8") as f:
        f.write(response)

    print(f"[DEBUG] Raw Qwen response saved: {debug_file}")
    parsed = extract_json_object(response)

    Path(output_file).write_text(
        json.dumps(parsed, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )



    return output_file


