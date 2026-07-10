#!/usr/bin/env python3 from future import annotations

import argparse
import importlib
import sys

def parse_arguments():
    """
    Parses command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(description="Cyber Security Tool - Mode: pentest/redteam")
    parser.add_argument("--mode", required=True, choices=["pentest", "redteam"], help="Operation to perform")
    parser.add_argument("--domain", help="Domain to analyze (optional)")
    parser.add_argument("--target", help="Target URL (e.g., https://app.alwaysoncyber.com)")
    return parser.parse_args()

def main():
    """
    Main function to execute the script.
    """
    args = parse_arguments()

    # Validate arguments
    if args.mode not in ["pentest", "redteam"]:
        print("Invalid mode. Use 'pentest' or 'redteam'.")
        sys.exit(1)

    if not args.target:
        print("The --target parameter is required.")
        sys.exit(1)

    # Import the web module
    try:
        module = importlib.import_module("core.web")
    except ImportError:
        print("Error: The 'core/web.py' module was not found.")
        sys.exit(1)

    # Execute the corresponding function
    if args.mode == "pentest":
        module.pentest_web(args.target)
    elif args.mode == "redteam":
        module.redteam_web(args.target)

if __name__ == "__main__":
    main()

