import sys
import xml.etree.ElementTree as ET
import requests

# ANSI escape codes for color
GREEN = '\033[92m'
BLUE = '\033[94m'
RED = '\033[91m'
RESET = '\033[0m'

def get_cve_data(cpe_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:{cpe_name}&isVulnerable"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve data for CPE: {cpe_name}")
        return None

def extract_cves(cve_data):
    if cve_data is None:
        return []
    cves = []
    vulnerabilities = cve_data.get("vulnerabilities", [])
    for vulnerability in vulnerabilities:
        cve_id = vulnerability.get("cve", {}).get("id", "")
        if cve_id:
            cves.append(cve_id)
    return cves

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cvechecker.py file.xml")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    tree = ET.parse(xml_file)
    root = tree.getroot()

    cpe_values = []
    for elem in root.iter():
        if 'cpe' in elem.tag:
            cpe_value = elem.text
            # Remove "cpe:/" prefix from CPE value
            cpe_value = cpe_value[5:] if cpe_value.startswith("cpe:/") else cpe_value
            cpe_values.append(cpe_value)

    for cpe_value in cpe_values:
        cve_data = get_cve_data(cpe_value)
        cves = extract_cves(cve_data)
        print(f"CVEs for CPE {cpe_value}:")
        
        if not cves:
            print(f"{RED}No CVEs found{RESET}")
        else:
            print(f"{GREEN}{', '.join(cves)}{RESET}")
            print(f"{BLUE}Total CVEs: {len(cves)}{RESET}")

if __name__ == "__main__":
    main()
