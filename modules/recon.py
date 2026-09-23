import subprocess
import xml.etree.ElementTree as ET
import os

def run_port_scan(target):
    print(f"[*] Executing live Nmap service scan on {target}...")
    xml_output = "scan_results.xml"
    
    # Run optimized Nmap command (-T4 fast, -F top 100 ports, -sV service detection, -oX XML output)
    command = ["nmap", "-T4", "-F", "-sV", "-oX", xml_output, target]
    
    try:
        # Execute silently so it doesn't spam stdout, or let it run
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap scan execution failed: {e}")
        return []
    except FileNotFoundError:
        print("[!] Error: Nmap is not installed or not found in system PATH.")
        return []

    open_ports = []
    
    # Parse the generated XML report
    if os.path.exists(xml_output):
        try:
            tree = ET.parse(xml_output)
            root = tree.getroot()
            
            for host in root.findall('host'):
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        portid = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state_elem = port.find('state')
                        state = state_elem.get('state') if state_elem is not None else "unknown"
                        
                        service_elem = port.find('service')
                        service_name = service_elem.get('name') if service_elem is not None else "unknown"
                        
                        if state == 'open':
                            open_ports.append({
                                "port": int(portid),
                                "protocol": protocol,
                                "service": service_name,
                                "state": state
                            })
                            print(f"    [+] Discovered open port: {portid}/{protocol} ({service_name})")
        except ET.ParseError:
            print("[!] Error parsing Nmap XML data tree.")
        
        # Clean up temporary XML artifact
        os.remove(xml_output)
    
    return open_ports