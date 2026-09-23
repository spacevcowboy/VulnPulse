#!/usr/bin/env python3
import argparse
import sys
from datetime import datetime
from modules.recon import run_port_scan
from modules.http_audit import run_http_audit
from utils.reporter import generate_summary

def banner():
    print(r"""
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██████╗ ██╗   ██╗██╗     ███████╗
    ██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██║   ██║██║     ██╔════╝
    ██║   ██║██║   ██║██║     ██╔██╗ ██║██████╔╝██║   ██║██║     ███████╗
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔═══╝ ██║   ██║██║     ╚╚══██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝███████╗███████║
    """)
    print("[-] Automated Vulnerability Orchestrator & Triage Engine v1.0\n")

def main():
    parser = argparse.ArgumentParser(description="VulnPulse Automated Security Orchestrator")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP address")
    args = parser.parse_args()

    banner()
    target = args.target
    start_time = datetime.now()

    # Centralized findings dictionary to store results from all modules
    audit_results = {
        "target": target,
        "timestamp": str(start_time),
        "open_ports": [],
        "http_findings": {},
        "risk_score": "Low"
    }

    print(f"[*] Starting automated assessment against: {target}\n")

    # Module 1: Port Scan & Service Fingerprinting
    print("--- [ Phase 1: Network & Port Recon ] ---")
    audit_results["open_ports"] = run_port_scan(target)

    # Module 2: HTTP Security & Endpoint Audit
    print("\n--- [ Phase 2: HTTP & Application Audit ] ---")
    audit_results["http_findings"] = run_http_audit(target)

    # Module 3: Report Aggregation & Summarization
    print("\n--- [ Phase 3: Generating Executive Summary ] ---")
    generate_summary(audit_results)

    end_time = datetime.now()
    print(f"\n[+] Assessment completed in {end_time - start_time}")

if __name__ == "__main__":
    main()