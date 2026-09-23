import requests
from requests.exceptions import RequestException

def run_http_audit(target):
    print(f"[*] Inspecting HTTP/HTTPS security posture for {target}...")
    
    # Ensure target has a scheme or default to building URLs
    urls_to_test = [f"https://{target}", f"http://{target}"]
    active_url = None
    response = None
    
    for url in urls_to_test:
        try:
            print(f"    [*] Attempting connection to {url}...")
            # 5-second timeout so it doesn't hang on dead ports
            response = requests.get(url, timeout=5, allow_redirects=True)
            active_url = url
            print(f"    [+] Connected successfully! Status Code: {response.status_code}")
            break
        except RequestException:
            print(f"    [!] Connection failed or timed out for {url}")
            continue

    if not response:
        return {
            "status": "unreachable",
            "secure_headers_found": [],
            "missing_headers": []
        }

    # Define critical security headers to check for
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection"
    ]
    
    found_headers = []
    missing_headers = []
    
    for header in security_headers:
        if header.lower() in [h.lower() for h in response.headers.keys()]:
            found_headers.append(header)
        else:
            missing_headers.append(header)

    print(f"    [+] Security Headers Present: {len(found_headers)}/{len(security_headers)}")
    for h in found_headers:
        print(f"        - Found: {h}")
    for h in missing_headers:
        print(f"        - Missing: {h}")

    return {
        "url": active_url,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "Unknown"),
        "secure_headers_present": found_headers,
        "missing_headers": missing_headers
    }