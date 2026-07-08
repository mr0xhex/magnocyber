#!/usr/bin/env python3

import requests


MODEL_NAME = "rabbit-direto"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


def run_rabbit(prompt):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        },
        timeout=300
    )

    response.raise_for_status()

    data = response.json()

    return data["response"].strip()
