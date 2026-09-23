import json
from datetime import datetime

def generate_summary(results):
    print(f"[*] Processing telemetry for {results['target']}...")
    
    open_ports = results.get("open_ports", [])
    http_findings = results.get("http_findings", {})
    missing_headers = http_findings.get("missing_headers", [])
    
    # Simple risk scoring logic based on findings
    risk_level = "Low"
    score_reasons = []
    
    if len(open_ports) > 3:
        risk_level = "Medium"
        score_reasons.append("Multiple open ports exposed")
        
    if len(missing_headers) >= 3:
        if risk_level == "Low":
            risk_level = "Medium"
        score_reasons.append(f"Multiple security headers missing ({len(missing_headers)}/5)")

    # Check for critical administrative ports
    critical_ports = [21, 23, 3389, 445]
    for p in open_ports:
        if p["port"] in critical_ports:
            risk_level = "High"
            score_reasons.append(f"Critical administrative port exposed: {p['port']}")

    results["risk_score"] = risk_level
    results["risk_reasons"] = score_reasons

    # Print Executive Summary to Console
    print("\n" + "="*50)
    print("           VULNPULSE EXECUTIVE SUMMARY           ")
    print("="*50)
    print(f" Target Host  : {results['target']}")
    print(f" Timestamp    : {results['timestamp']}")
    print(f" Risk Rating  : {risk_level}")
    if score_reasons:
        print(" Risk Factors :")
        for reason in score_reasons:
            print(f"   - {reason}")
    print("-"*50)
    print(f" Open Ports   : {len(open_ports)} detected")
    for p in open_ports:
        print(f"   [+] {p['port']}/{p['protocol']} -> {p['service'].upper()}")
        
    print("-"*50)
    if http_findings.get("status") == "unreachable":
        print(" Web Service  : Unreachable or closed")
    else:
        print(f" Web URL      : {http_findings.get('url')}")
        print(f" HTTP Status  : {http_findings.get('status_code')}")
        print(f" Server Tech  : {http_findings.get('server')}")
        print(f" Headers Deficit: {len(missing_headers)}/5 missing")
    print("="*50)

    # Automatically save a JSON report artifact for documentation
    report_filename = f"report_{results['target'].replace('.', '_')}.json"
    try:
        with open(report_filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Detailed scan artifact saved to: {report_filename}")
    except IOError as e:
        print(f"[!] Failed to save report artifact: {e}")