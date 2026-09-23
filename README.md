VulnPulse 🔍

VulnPulse is a lightweight, modular security assessment orchestrator built in Python 3. It automates initial target reconnaissance, service enumeration, HTTP security header auditing, and dynamic risk scoring into a single unified pipeline.

📖 Documentation & User Guide

For complete installation steps, architecture breakdowns, usage instructions, and sample execution outputs, please refer to the included VulnPulse User Guide & Documentation (PDF).

🚀 Architecture

vulnpulse/
├── modules/
│   ├── __init__.py
│   ├── recon.py       # Automated Nmap execution and XML tree parsing
│   └── http_audit.py  # HTTPS/HTTP fallback and security header analysis
├── utils/
│   └── reporter.py    # Aggregates telemetry, calculates risk scores, and exports JSON reports
└── main.py            # Core engine and argument parsing controller


⚙️ Quick Start

Ensure Python 3, Nmap, and dependencies are installed:

pip install requests


Run the orchestrator against an authorized target:

python3 main.py -t scanme.nmap.org


🛡️ License

For educational and authorized security auditing purposes only.
