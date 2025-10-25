#!/usr/bin/env python3
import sys
import requests
import urllib.parse
import time
import random
import string
import re
import os
from colorama import Fore, Style, init

init(autoreset=True)

class MultiVulnerabilityScanner:
    def __init__(self, target_url, scan_type="all"):
        self.target_url = target_url
        self.session = requests.Session()
        self.scan_type = scan_type
        self.vulnerabilities = []

        self.baseline_response = None
        self.baseline_length = 0

        self.sql_payloads = self.load_payloads_from_file("sql.txt", "SQL")
        self.xss_payloads = self.load_payloads_from_file("xss.txt", "XSS")
        self.rce_payloads = self.load_payloads_from_file("rce.txt", "RCE")
        self.lfi_payloads = self.load_payloads_from_file("lfi.txt", "LFI")
        self.rfi_payloads = self.load_payloads_from_file("rfi.txt", "RFI")

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

    def extract_params(self):
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []

    def load_payloads_from_file(self, filename, payload_type):
        payloads = []
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        clean_line = line.replace('-xss', '').replace('-sql', '').replace('-rce', '').replace('-lfi', '').replace('-rfi', '').strip()
                        clean_line = clean_line.replace('-XSS', '').replace('-SQL', '').replace('-RCE', '').replace('-LFI', '').replace('-RFI', '').strip()

                        if clean_line and not clean_line.startswith("#"):
                            payloads.append({
                                "payload": clean_line,
                                "type": payload_type
                            })
                print(f"{Fore.GREEN}[INFO] Loaded {len(payloads)} {payload_type} payloads from {filename}")
            else:
                print(f"{Fore.YELLOW}[WARNING] File {filename} not found!")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Error loading {filename}: {e}")

        return payloads

    def get_baseline(self, param):
        if self.baseline_response is None:
            response, _ = self.send_payload(param, "1")
            if response:
                self.baseline_response = response
                self.baseline_length = len(response.text)
        return self.baseline_response, self.baseline_length

    def send_payload(self, param, payload, method="GET"):
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)

            original_value = params[param][0] if param in params else "test"
            params[param] = [payload]

            new_query = urllib.parse.urlencode(params, doseq=True)
            target_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            response = self.session.get(target_url, timeout=10, verify=False)
            return response, original_value

        except Exception as e:
            return None, None

    def generate_random_string(self, length=12):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def is_sql_error(self, response):
        if not response:
            return False

        error_indicators = [
            'sql syntax', 'mysql', 'microsoft odbc', 'oracle', 'postgresql',
            'warning', 'error', 'exception', 'unclosed quotation',
            'quoted string', 'sqlserver', 'odbc', 'driver', 'database',
            'you have an error', 'supplied argument', 'unknown column',
            'mysqli', 'pdo', 'sqlite', 'mariadb', 'mssql'
        ]

        content = response.text.lower()
        return any(error in content for error in error_indicators)

    def is_blind_sql(self, response, baseline_length):
        if not response:
            return False

        current_length = len(response.text)
        length_diff = abs(current_length - baseline_length)

        if baseline_length > 0 and length_diff > (baseline_length * 0.1):
            return True

        return False

    def is_xss_vulnerable(self, response, payload):
        if not response:
            return False

        if payload in response.text:
            return True

        xss_patterns = [
            f'<script>{payload}</script>',
            f'"{payload}"',
            f"'{payload}'",
            f'<div>{payload}</div>',
            f'onmouseover={payload}',
            f'onclick={payload}'
        ]

        return any(pattern in response.text for pattern in xss_patterns)

    def is_rce_vulnerable(self, response, payload, random_marker):
        if not response:
            return False

        if random_marker and random_marker in response.text:
            return True

        rce_indicators = [
            'root:', 'bin/bash', 'daemon:', 'sys:', 'www-data:',
            'administrator', 'windows', 'system32', 'program files',
            'uid=', 'gid=', 'groups=', 'login@', 'hostname:',
            'cannot', 'command not found', 'permission denied', 'no such file'
        ]

        content = response.text.lower()

        if any(indicator in content for indicator in rce_indicators):
            return True

        if len(response.text) != self.baseline_length:
            if abs(len(response.text) - self.baseline_length) > 50:
                return True

        return False

    def is_lfi_vulnerable(self, response, payload):
        if not response:
            return False

        lfi_indicators = [
            'root:', 'www-data:', '/etc/passwd', '/etc/shadow',
            'boot.ini', 'win.ini', 'system.ini', '<?php',
            '<?=', 'warning', 'error', 'failed to open',
            'no such file', 'file not found', 'cannot open',
            'permission denied'
        ]

        content = response.text.lower()

        if any(indicator in content for indicator in lfi_indicators):
            return True

        file_content_patterns = [
            r'root:.*:0:0:',
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]'
        ]

        for pattern in file_content_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True

        return False

    def is_rfi_vulnerable(self, response, payload):
        if not response:
            return False

        rfi_indicators = [
            '<?php', '<?=', 'warning', 'error', 'failed to open',
            'include_path', 'allow_url_include', 'remote file',
            'cannot open', 'url file-access', 'http://', 'https://',
            'ftp://', 'php://', 'data://'
        ]

        content = response.text.lower()

        if any(indicator in content for indicator in rfi_indicators):
            return True

        if 'google' in payload and 'google' in response.text:
            return True

        return False

    def test_parameter_sql(self, param):
        if not self.sql_payloads:
            return

        print(f"{Fore.CYAN}[INFO] Testing parameter {param} for SQL Injection...")

        baseline_response, baseline_length = self.get_baseline(param)

        for i, payload_info in enumerate(self.sql_payloads, 1):
            payload = payload_info["payload"]

            print(f"{Fore.WHITE}[INFO] Payload checked {i}/{len(self.sql_payloads)}: {payload[:50]}...")

            response, original_value = self.send_payload(param, payload)

            if response:
                if self.is_sql_error(response):
                    print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: SQL Injection")
                    print(f"{Fore.RED}[PAYLOAD] {payload}")

                    self.vulnerabilities.append({
                        "parameter": param,
                        "type": "SQL Injection",
                        "payload": payload,
                        "original_value": original_value,
                        "severity": "HIGH"
                    })
                    break

                if self.is_blind_sql(response, baseline_length):
                    print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: Blind SQL Injection")
                    print(f"{Fore.RED}[PAYLOAD] {payload}")

                    self.vulnerabilities.append({
                        "parameter": param,
                        "type": "Blind SQL Injection",
                        "payload": payload,
                        "original_value": original_value,
                        "severity": "HIGH"
                    })
                    break

    def test_parameter_xss(self, param):
        if not self.xss_payloads:
            return

        print(f"{Fore.CYAN}[INFO] Testing parameter {param} for XSS...")

        for i, payload_info in enumerate(self.xss_payloads, 1):
            payload = payload_info["payload"]

            print(f"{Fore.WHITE}[INFO] Payload checked {i}/{len(self.xss_payloads)}: {payload[:50]}...")

            response, original_value = self.send_payload(param, payload)

            if response and self.is_xss_vulnerable(response, payload):
                print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: XSS")
                print(f"{Fore.RED}[PAYLOAD] {payload}")

                self.vulnerabilities.append({
                    "parameter": param,
                    "type": "XSS",
                    "payload": payload,
                    "original_value": original_value,
                    "severity": "MEDIUM"
                })
                break

    def test_parameter_rce(self, param):
        if not self.rce_payloads:
            return

        print(f"{Fore.CYAN}[INFO] Testing parameter {param} for RCE...")

        baseline_response, baseline_length = self.get_baseline(param)

        for i, payload_info in enumerate(self.rce_payloads, 1):
            payload_template = payload_info["payload"]
            random_marker = self.generate_random_string(12)
            payload = payload_template.replace("MARKER", random_marker)

            print(f"{Fore.WHITE}[INFO] Payload checked {i}/{len(self.rce_payloads)}: {payload[:50]}...")

            response, original_value = self.send_payload(param, payload)

            if response and self.is_rce_vulnerable(response, payload, random_marker):
                print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: RCE")
                print(f"{Fore.RED}[PAYLOAD] {payload}")
                print(f"{Fore.RED}[MARKER] {random_marker}")

                self.vulnerabilities.append({
                    "parameter": param,
                    "type": "RCE",
                    "payload": payload,
                    "original_value": original_value,
                    "severity": "CRITICAL"
                })
                break

    def test_parameter_lfi(self, param):
        if not self.lfi_payloads:
            return

        print(f"{Fore.CYAN}[INFO] Testing parameter {param} for LFI...")

        for i, payload_info in enumerate(self.lfi_payloads, 1):
            payload = payload_info["payload"]

            print(f"{Fore.WHITE}[INFO] Payload checked {i}/{len(self.lfi_payloads)}: {payload[:50]}...")

            response, original_value = self.send_payload(param, payload)

            if response and self.is_lfi_vulnerable(response, payload):
                print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: LFI")
                print(f"{Fore.RED}[PAYLOAD] {payload}")

                self.vulnerabilities.append({
                    "parameter": param,
                    "type": "LFI",
                    "payload": payload,
                    "original_value": original_value,
                    "severity": "HIGH"
                })
                break

    def test_parameter_rfi(self, param):
        if not self.rfi_payloads:
            return

        print(f"{Fore.CYAN}[INFO] Testing parameter {param} for RFI...")

        for i, payload_info in enumerate(self.rfi_payloads, 1):
            payload = payload_info["payload"]

            print(f"{Fore.WHITE}[INFO] Payload checked {i}/{len(self.rfi_payloads)}: {payload[:50]}...")

            response, original_value = self.send_payload(param, payload)

            if response and self.is_rfi_vulnerable(response, payload):
                print(f"{Fore.RED}[CRITICAL] GET parameter \"{param}\" vulnerability: RFI")
                print(f"{Fore.RED}[PAYLOAD] {payload}")

                self.vulnerabilities.append({
                    "parameter": param,
                    "type": "RFI",
                    "payload": payload,
                    "original_value": original_value,
                    "severity": "HIGH"
                })
                break

    def interactive_sql_shell(self, param):
        print(f"{Fore.GREEN}[INFO] Starting interactive SQL shell for parameter: {param}")
        print(f"{Fore.GREEN}[INFO] Enter your SQL injections (type 'exit' to quit):")

        while True:
            payload = input(f"{Fore.CYAN}SQL> ").strip()
            if payload.lower() == 'exit':
                break

            response, original_value = self.send_payload(param, payload)
            if response:
                print(f"{Fore.WHITE}[STATUS] Response code: {response.status_code}")
                print(f"{Fore.WHITE}[LENGTH] Response length: {len(response.text)}")

                if self.is_sql_error(response):
                    print(f"{Fore.RED}[VULNERABLE] SQL injection detected!")
                else:
                    print(f"{Fore.GREEN}[SAFE] No SQL injection detected")

                print(f"{Fore.WHITE}[RESPONSE PREVIEW]:")
                print(response.text[:500])
                print(f"{Fore.WHITE}...")
            else:
                print(f"{Fore.RED}[ERROR] No response from server")

    def interactive_xss_shell(self, param):
        print(f"{Fore.GREEN}[INFO] Starting interactive XSS shell for parameter: {param}")
        print(f"{Fore.GREEN}[INFO] Enter your XSS payloads (type 'exit' to quit):")

        while True:
            payload = input(f"{Fore.CYAN}XSS> ").strip()
            if payload.lower() == 'exit':
                break

            response, original_value = self.send_payload(param, payload)
            if response:
                print(f"{Fore.WHITE}[STATUS] Response code: {response.status_code}")
                print(f"{Fore.WHITE}[LENGTH] Response length: {len(response.text)}")

                if self.is_xss_vulnerable(response, payload):
                    print(f"{Fore.RED}[VULNERABLE] XSS vulnerability detected!")
                else:
                    print(f"{Fore.GREEN}[SAFE] No XSS detected")

                if payload in response.text:
                    print(f"{Fore.YELLOW}[REFLECTED] Payload reflected in response")
                else:
                    print(f"{Fore.BLUE}[NOT REFLECTED] Payload not reflected")
            else:
                print(f"{Fore.RED}[ERROR] No response from server")

    def interactive_rce_shell(self, param):
        print(f"{Fore.GREEN}[INFO] Starting interactive RCE shell for parameter: {param}")
        print(f"{Fore.GREEN}[INFO] Enter your RCE payloads (type 'exit' to quit):")

        baseline_response, baseline_length = self.get_baseline(param)

        while True:
            payload = input(f"{Fore.CYAN}RCE> ").strip()
            if payload.lower() == 'exit':
                break

            random_marker = self.generate_random_string(12)
            full_payload = payload + f"; echo {random_marker}"

            response, original_value = self.send_payload(param, full_payload)
            if response:
                print(f"{Fore.WHITE}[STATUS] Response code: {response.status_code}")
                print(f"{Fore.WHITE}[LENGTH] Response length: {len(response.text)}")

                if self.is_rce_vulnerable(response, full_payload, random_marker):
                    print(f"{Fore.RED}[VULNERABLE] RCE vulnerability detected!")
                else:
                    print(f"{Fore.GREEN}[SAFE] No RCE detected")
            else:
                print(f"{Fore.RED}[ERROR] No response from server")

    def interactive_lfi_shell(self, param):
        print(f"{Fore.GREEN}[INFO] Starting interactive LFI shell for parameter: {param}")
        print(f"{Fore.GREEN}[INFO] Enter your LFI payloads (type 'exit' to quit):")

        while True:
            payload = input(f"{Fore.CYAN}LFI> ").strip()
            if payload.lower() == 'exit':
                break

            response, original_value = self.send_payload(param, payload)
            if response:
                print(f"{Fore.WHITE}[STATUS] Response code: {response.status_code}")
                print(f"{Fore.WHITE}[LENGTH] Response length: {len(response.text)}")

                if self.is_lfi_vulnerable(response, payload):
                    print(f"{Fore.RED}[VULNERABLE] LFI vulnerability detected!")
                else:
                    print(f"{Fore.GREEN}[SAFE] No LFI detected")
            else:
                print(f"{Fore.RED}[ERROR] No response from server")

    def interactive_rfi_shell(self, param):
        print(f"{Fore.GREEN}[INFO] Starting interactive RFI shell for parameter: {param}")
        print(f"{Fore.GREEN}[INFO] Enter your RFI payloads (type 'exit' to quit):")

        while True:
            payload = input(f"{Fore.CYAN}RFI> ").strip()
            if payload.lower() == 'exit':
                break

            response, original_value = self.send_payload(param, payload)
            if response:
                print(f"{Fore.WHITE}[STATUS] Response code: {response.status_code}")
                print(f"{Fore.WHITE}[LENGTH] Response length: {len(response.text)}")

                if self.is_rfi_vulnerable(response, payload):
                    print(f"{Fore.RED}[VULNERABLE] RFI vulnerability detected!")
                else:
                    print(f"{Fore.GREEN}[SAFE] No RFI detected")
            else:
                print(f"{Fore.RED}[ERROR] No response from server")

    def scan(self):
        print(f"{Fore.GREEN}[INFO] Starting scan for: {self.target_url}")
        print(f"{Fore.GREEN}[INFO] Scan type: {self.scan_type.upper()}")

        params = self.extract_params()
        if not params:
            print(f"{Fore.YELLOW}[INFO] No parameters found in URL")
            return

        print(f"{Fore.GREEN}[INFO] Found parameters: {', '.join(params)}")
        print("-" * 80)

        for param in params:
            self.baseline_response = None
            self.baseline_length = 0

            if self.scan_type in ["all", "sql"]:
                self.test_parameter_sql(param)

            if self.scan_type in ["all", "xss"]:
                self.test_parameter_xss(param)

            if self.scan_type in ["all", "rce"]:
                self.test_parameter_rce(param)

            if self.scan_type in ["all", "lfi"]:
                self.test_parameter_lfi(param)

            if self.scan_type in ["all", "rfi"]:
                self.test_parameter_rfi(param)

            print("-" * 80)

    def generate_report(self):
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}SCAN REPORT")
        print(f"{Fore.GREEN}{'='*80}")

        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[RESULT] No vulnerabilities found")
            return

        sql_vulns = [v for v in self.vulnerabilities if "SQL" in v["type"]]
        xss_vulns = [v for v in self.vulnerabilities if v["type"] == "XSS"]
        rce_vulns = [v for v in self.vulnerabilities if v["type"] == "RCE"]
        lfi_vulns = [v for v in self.vulnerabilities if v["type"] == "LFI"]
        rfi_vulns = [v for v in self.vulnerabilities if v["type"] == "RFI"]

        print(f"\n{Fore.GREEN}[SUMMARY]")
        print(f"{Fore.GREEN}SQL Injections: {len(sql_vulns)}")
        print(f"{Fore.GREEN}XSS: {len(xss_vulns)}")
        print(f"{Fore.GREEN}RCE: {len(rce_vulns)}")
        print(f"{Fore.GREEN}LFI: {len(lfi_vulns)}")
        print(f"{Fore.GREEN}RFI: {len(rfi_vulns)}")
        print(f"{Fore.GREEN}Total: {len(self.vulnerabilities)}")

        print(f"\n{Fore.GREEN}[DETAILS]")
        for i, vuln in enumerate(self.vulnerabilities, 1):
            if vuln["severity"] == "CRITICAL":
                color = Fore.RED + Style.BRIGHT
            elif vuln["severity"] == "HIGH":
                color = Fore.RED
            else:
                color = Fore.YELLOW

            print(f"\n{color}Vulnerability #{i}:")
            print(f"{color}  Type: {vuln['type']}")
            print(f"{color}  Parameter: {vuln['parameter']}")
            print(f"{color}  Payload: {vuln['payload']}")
            print(f"{color}  Severity: {vuln['severity']}")

def print_banner():
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════╗
║                        metaExplorer                                      ║
║                    create by StrangerMRX                                 ║
║      SQL + XSS + RCE + LFI + RFI Scanner + Interactive Shells            ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def main():
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python3 multi_scanner.py <url> [scan_type]")
        print("\nScan types:")
        print("  all, sql, xss, rce, lfi, rfi - automatic scanning")
        print("  sql-shell, xss-shell, rce-shell, lfi-shell, rfi-shell - interactive mode")
        print("\nExamples:")
        print("  python3 multi_scanner.py \"https://site.com/page.php?id=1\"")
        print("  python3 multi_scanner.py \"https://site.com/page.php?id=1\" sql")
        print("  python3 multi_scanner.py \"https://site.com/page.php?id=1\" sql-shell")
        print("  python3 multi_scanner.py \"https://site.com/page.php?id=1\" xss-shell")
        sys.exit(1)

    target_url = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "all"

    shell_modes = ["sql-shell", "xss-shell", "rce-shell", "lfi-shell", "rfi-shell"]
    valid_types = ["all", "sql", "xss", "rce", "lfi", "rfi"] + shell_modes

    if scan_type not in valid_types:
        print(f"{Fore.RED}[ERROR] Invalid scan type. Use: {', '.join(valid_types)}")
        sys.exit(1)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_banner()

    scanner = MultiVulnerabilityScanner(target_url, scan_type)

    if scan_type in shell_modes:
        params = scanner.extract_params()
        if not params:
            print(f"{Fore.YELLOW}[INFO] No parameters found in URL")
            return

        if len(params) == 1:
            param = params[0]
        else:
            print(f"{Fore.GREEN}[INFO] Available parameters:")
            for i, p in enumerate(params, 1):
                print(f"  {i}. {p}")
            try:
                choice = int(input(f"{Fore.CYAN}Select parameter (1-{len(params)}): ")) - 1
                param = params[choice]
            except:
                print(f"{Fore.RED}[ERROR] Invalid choice, using first parameter")
                param = params[0]

        if scan_type == "sql-shell":
            scanner.interactive_sql_shell(param)
        elif scan_type == "xss-shell":
            scanner.interactive_xss_shell(param)
        elif scan_type == "rce-shell":
            scanner.interactive_rce_shell(param)
        elif scan_type == "lfi-shell":
            scanner.interactive_lfi_shell(param)
        elif scan_type == "rfi-shell":
            scanner.interactive_rfi_shell(param)
    else:
        scanner.scan()
        scanner.generate_report()

if __name__ == "__main__":
    main()

