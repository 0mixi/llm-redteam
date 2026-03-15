#!/usr/bin/env python3
"""
LLM Red Teaming Framework
Author: Om Awachar
Description: Automated adversarial testing framework for LLM-based applications.
Covers prompt injection, jailbreaking, data leakage, and model abuse.
"""

import json
import csv
import time
import argparse
import requests
from datetime import datetime
from pathlib import Path
from utils.reporter import generate_report
from tests.prompt_injection import run_prompt_injection_tests
from tests.jailbreak import run_jailbreak_tests
from tests.data_leakage import run_data_leakage_tests
from tests.model_abuse import run_model_abuse_tests

BANNER = """
╦  ╦  ╔╦╗  ╦═╗  ╔═╗  ╔╦╗  ╔╦╗  ╔═╗  ╔═╗  ╔╦╗
║  ║  ║║║  ╠╦╝  ║╣    ║║   ║    ║╣   ╠═╣  ║║║
╩═╝  ╩  ╩ ╩  ╩╚═  ╚═╝  ═╩╝  ╩    ╚═╝  ╩ ╩  ╩ ╩
LLM Red Teaming Framework v1.0 — by Om Awachar
"""

def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return json.load(f)

def run_all_tests(target_url: str, api_key: str, model: str, output_dir: str):
    print(BANNER)
    print(f"[*] Target: {target_url}")
    print(f"[*] Model:  {model}")
    print(f"[*] Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    results = {
        "metadata": {
            "target": target_url,
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "tester": "Om Awachar"
        },
        "findings": []
    }

    test_suites = [
        ("Prompt Injection",   run_prompt_injection_tests),
        ("Jailbreaking",       run_jailbreak_tests),
        ("Sensitive Data Leakage", run_data_leakage_tests),
        ("Model Abuse",        run_model_abuse_tests),
    ]

    for suite_name, suite_fn in test_suites:
        print(f"\n[+] Running: {suite_name}")
        suite_results = suite_fn(target_url, api_key, model)
        results["findings"].extend(suite_results)
        passed  = sum(1 for r in suite_results if r["status"] == "VULNERABLE")
        print(f"    → {passed}/{len(suite_results)} tests flagged vulnerabilities")

    # Save raw JSON
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    json_path = out_path / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    # Generate HTML report
    report_path = generate_report(results, output_dir)

    print(f"\n[✓] JSON results : {json_path}")
    print(f"[✓] HTML report  : {report_path}")
    return results

def main():
    parser = argparse.ArgumentParser(description="LLM Red Teaming Framework")
    parser.add_argument("--target",  required=True,  help="Target API endpoint URL")
    parser.add_argument("--api-key", required=False, default="", help="API key for target")
    parser.add_argument("--model",   required=False, default="gpt-3.5-turbo", help="Model name")
    parser.add_argument("--output",  required=False, default="reports/", help="Output directory")
    parser.add_argument("--config",  required=False, help="Path to JSON config file")
    args = parser.parse_args()

    if args.config:
        cfg = load_config(args.config)
        args.target  = cfg.get("target",  args.target)
        args.api_key = cfg.get("api_key", args.api_key)
        args.model   = cfg.get("model",   args.model)
        args.output  = cfg.get("output",  args.output)

    run_all_tests(args.target, args.api_key, args.model, args.output)

if __name__ == "__main__":
    main()
