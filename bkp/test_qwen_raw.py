import argparse
from pathlib import Path

from core.qwen_engine import analyze_evidence


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--raw",
        required=True,
        help="Path to raw evidence file"
    )

    parser.add_argument(
        "--prompt",
        default="prompts/web_pentest.txt"
    )

    parser.add_argument(
        "--output",
        default=None
    )

    args = parser.parse_args()

    raw_file = Path(args.raw)

    if not raw_file.exists():
        raise SystemExit(f"Raw file not found: {raw_file}")

    output_file = args.output

    if output_file is None:
        output_file = str(raw_file).replace("_raw.txt", "_findings.json")

    analyze_evidence(
        prompt_file=args.prompt,
        evidence_file=str(raw_file),
        output_file=output_file,
        config={
            "ai": {
                "provider": "ollama",
                "model": "qwen3:8b"
            }
        }
    )

    print(f"Findings saved: {output_file}")


if __name__ == "__main__":
    main()
