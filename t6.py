import os
import socket
import requests
import urllib.parse
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import subprocess
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from random import randint
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FILE = os.path.join(BASE_DIR, f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

SQL_PAYLOAD_FOLDER = os.path.join(BASE_DIR, "sqlpayloads")
XSS_PAYLOAD_FOLDER = os.path.join(BASE_DIR, "xss_payloads")
WORDLIST_FOLDER = os.path.join(BASE_DIR, "wordlists")
LFI_PAYLOAD_FOLDER = os.path.join(BASE_DIR, "lfi_payloads")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

scan_results = {
    "open_ports": [],
    "sql_injection": [],
    "xss": [],
    "directories": [],
    "robots_txt": "",
    "lfi": []
}

stop_condition_met = False

def log_findings(message, severity="info", risk_level=1):
    global stop_condition_met
    risk_label = f" [Risk Level: {risk_level}]"
    
    if severity == "critical":
        print(f"{Colors.RED}[CRITICAL] {message}{risk_label}{Colors.RESET}")
    elif severity == "warning":
        print(f"{Colors.YELLOW}[WARNING] {message}{risk_label}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[INFO] {message}{risk_label}{Colors.RESET}")
    
    with open(REPORT_FILE, 'a') as report_file:
        report_file.write(f"[{severity.upper()}] {message}{risk_label}\n")

def check_sql_injection(url):
    if stop_condition_met:
        return
    if not os.path.exists(SQL_PAYLOAD_FOLDER):
        log_findings(f"SQL payload folder not found: {SQL_PAYLOAD_FOLDER}", "critical", 5)
        return
    
    payload_files = [os.path.join(SQL_PAYLOAD_FOLDER, f) for f in os.listdir(SQL_PAYLOAD_FOLDER) if f.endswith('.txt')]
    all_payloads = []

    for file_path in payload_files:
        with open(file_path, 'r') as file:
            all_payloads.extend([line.strip() for line in file if line.strip()])

    def test_payload(payload):
        if stop_condition_met:
            return
        try:
            response = requests.get(url + payload, timeout=5)
            if "error" in response.text or "syntax" in response.text:
                scan_results["sql_injection"].append(payload)
                log_findings(f"Potential SQL Injection detected with payload: {payload}", "critical", 5)
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_payload, all_payloads)

def check_xss(url):
    if stop_condition_met:
        return
    if not os.path.exists(XSS_PAYLOAD_FOLDER):
        log_findings(f"XSS payload folder not found: {XSS_PAYLOAD_FOLDER}", "critical", 5)
        return
    
    payload_files = [os.path.join(XSS_PAYLOAD_FOLDER, f) for f in os.listdir(XSS_PAYLOAD_FOLDER) if f.endswith('.txt')]
    all_payloads = []

    for file_path in payload_files:
        with open(file_path, 'r') as file:
            all_payloads.extend([line.strip() for line in file if line.strip()])

    def test_payload(payload):
        if stop_condition_met:
            return
        try:
            response = requests.get(url + payload, timeout=5)
            if payload in response.text:
                scan_results["xss"].append(payload)
                log_findings(f"Potential XSS detected at {url} with payload: {payload}", "critical", 4)
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_payload, all_payloads)

def dir_bruteforce(url):
    if stop_condition_met:
        return
    if not os.path.exists(WORDLIST_FOLDER):
        log_findings(f"Wordlist folder not found: {WORDLIST_FOLDER}", "critical", 5)
        return

    wordlist_files = [os.path.join(WORDLIST_FOLDER, f) for f in os.listdir(WORDLIST_FOLDER) if f.endswith('.txt')]
    
    all_wordlists = []

    for file_path in wordlist_files:
        with open(file_path, 'r') as file:
            all_wordlists.extend([line.strip() for line in file if line.strip()])

    def test_directory(directory):
        if stop_condition_met:
            return
        dir_url = urllib.parse.urljoin(url, directory)
        try:
            response = requests.get(dir_url, timeout=5)
            if response.status_code == 200:
                scan_results["directories"].append(dir_url)
                risk = 4 if 'admin' in directory or 'backup' in directory else 2
                log_findings(f"Found accessible directory: {dir_url}", "warning", risk)
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_directory, all_wordlists)

def check_robots_txt(url):
    if stop_condition_met:
        return
    try:
        robots_url = urllib.parse.urljoin(url, "robots.txt")
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            scan_results["robots_txt"] = response.text
            log_findings(f"robots.txt found at {robots_url}", "info", 1)
    except requests.RequestException:
        pass

def check_open_ports(target):
    log_findings(f"\n===== Scanning Open Ports on {target} =====", "info", 1)
    common_ports = [20, 21, 22, 23, 25, 53, 80, 137, 139, 443, 445, 8080, 8443, 3389, 1433, 3306]
    
    def test_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            risk = 4 if port in [22, 3389, 445] else 3
            scan_results["open_ports"].append((port, risk))
            log_findings(f"Port {port} is open", "warning", risk)

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_port, common_ports)

def generate_lfi_payloads():
    base_payloads = [
        "/etc/passwd",
        "/etc/hosts",
        "/proc/self/environ",
        "C:\\boot.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]

    external_payloads = []
    if os.path.exists(LFI_PAYLOAD_FOLDER):
        payload_files = [os.path.join(LFI_PAYLOAD_FOLDER, f) for f in os.listdir(LFI_PAYLOAD_FOLDER) if f.endswith('.txt')]
        for file_path in payload_files:
            with open(file_path, "r") as file:
                external_payloads.extend([line.strip() for line in file if line.strip()])
    else:
        log_findings("LFI payload folder not found. Proceeding with base payloads only.", "warning", 3)

    traversal_patterns = ["../", "..\\"] * randint(1, 6)
    return base_payloads + external_payloads + [
        f"{t}{f}" for t in traversal_patterns for f in (base_payloads + external_payloads)
    ]

def check_lfi(url):
    if stop_condition_met:
        return
    payloads = generate_lfi_payloads()

    def test_payload(payload):
        if stop_condition_met:
            return
        try:
            response = requests.get(url + payload, timeout=5)
            if "root" in response.text or "boot.ini" in response.text:
                scan_results["lfi"].append(payload)
                log_findings(f"Potential LFI detected at {url} with payload: {payload}", "critical", 4)
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_payload, payloads)

def save_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    json_report_file = os.path.join(BASE_DIR, f"audit_report_{timestamp}.json")
    total_vulnerabilities, summary = count_vulnerabilities()
    
    report_data = {
        "Summary": summary,
        "Total Vulnerabilities": total_vulnerabilities,
        "Details": scan_results
    }

    with open(json_report_file, 'w') as json_file:
        json.dump(report_data, json_file, indent=4)
    
    xml_report_file = os.path.join(BASE_DIR, f"audit_report_{timestamp}.xml")
    root = ET.Element("audit_report")
    summary_element = ET.SubElement(root, "Summary")
    for category, count in summary.items():
        ET.SubElement(summary_element, category.replace(" ", "_").lower()).text = str(count)
    
    total_element = ET.SubElement(root, "TotalVulnerabilities")
    total_element.text = str(total_vulnerabilities)
    
    details_element = ET.SubElement(root, "Details")
    for category, findings in scan_results.items():
        category_element = ET.SubElement(details_element, category)
        for finding in findings:
            ET.SubElement(category_element, "finding").text = str(finding)
    
    tree = ET.ElementTree(root)
    tree.write(xml_report_file)

    print(f"Audit report saved as JSON: {json_report_file}")
    print(f"Audit report saved as XML: {xml_report_file}")
    

def count_vulnerabilities():
    summary = {
        "Open Ports": len(scan_results["open_ports"]),
        "SQL Injection": len(scan_results["sql_injection"]),
        "XSS": len(scan_results["xss"]),
        "Directories": len(scan_results["directories"]),
        "robots.txt Found": 1 if scan_results["robots_txt"] else 0,
        "LFI": len(scan_results["lfi"]),
    }
    total_vulnerabilities = sum(summary.values())
    return total_vulnerabilities, summary
    
def pentest(url):
    target = urllib.parse.urlparse(url).hostname
    check_open_ports(target)
    check_sql_injection(url)
    check_xss(url)
    dir_bruteforce(url)
    check_robots_txt(url)
    check_lfi(url)

    if not stop_condition_met:
    	total_vulnerabilities, summary = count_vulnerabilities()
    	log_findings(f"Total vulnerabilities found: {total_vulnerabilities}", "info", 1)
    	for vuln_type, count in summary.items():
    	  log_findings(f"{vuln_type}: {count} found", "info", 1)
    	generate_graphical_reports(summary)  # Generate the graphical reports
    	save_report()
    else:
        print("Stopping the scan due to user interruption.")

def generate_graphical_reports(summary):
    
    categories = list(summary.keys())
    counts = list(summary.values())
    
    # Bar Chart
    plt.figure(figsize=(10, 6))
    plt.bar(categories, counts, color='skyblue')
    plt.title('Vulnerability Summary - Bar Chart')
    plt.xlabel('Vulnerability Types')
    plt.ylabel('Number of Vulnerabilities')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    bar_chart_path = os.path.join(BASE_DIR, 'vulnerability_summary_bar_chart.png')
    plt.savefig(bar_chart_path)
    print(f"Bar chart saved at {bar_chart_path}")
    plt.close()
    
    # Pie Chart
    plt.figure(figsize=(8, 8))
    plt.pie(counts, labels=categories, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
    plt.title('Vulnerability Summary - Pie Chart')
    pie_chart_path = os.path.join(BASE_DIR, 'vulnerability_summary_pie_chart.png')
    plt.savefig(pie_chart_path)
    print(f"Pie chart saved at {pie_chart_path}")
    plt.close()
            

def signal_handler(sig, frame):
    global stop_condition_met
    print("\nUser  interrupted the scan. Stopping gracefully...")
    stop_condition_met = True
    save_report()

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    target_url = input("Enter the target URL for pentesting: ")
    pentest(target_url)
    