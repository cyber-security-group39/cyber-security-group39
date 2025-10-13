import tkinter as tk
from tkinter import ttk, messagebox
from scanners.web_vuln_scanner import EliteWebVulnScanner
from utils.validation_utils import is_valid_url, normalize_url
from error_handler import error_handler
import threading

class WebScannerTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.create_widgets()
    
    def create_widgets(self):
        frame = self.frame
        
     
        ttk.Label(frame, text="Target URL:").grid(column=0, row=0, sticky='w', padx=10, pady=5)
        self.entry_web_url = ttk.Entry(frame, width=50)
        self.entry_web_url.grid(column=1, row=0, padx=10, pady=5)
        
       
        ttk.Label(frame, text="Select Tests:").grid(column=0, row=1, sticky='w', padx=10, pady=5)
        
        
        self.test_vars = {}
        tests = [
            ('ssl_tls', 'SSL/TLS Configuration'),
            ('security_headers', 'Security Headers'),
            ('cors', 'CORS Misconfiguration'),
            ('sql_injection', 'SQL Injection'),
            ('xss', 'Cross-Site Scripting (XSS)'),
            ('directory_traversal', 'Directory Traversal'),
            ('file_inclusion', 'File Inclusion'),
            ('command_injection', 'Command Injection'),
            ('ssrf', 'Server-Side Request Forgery'),
            ('xxe', 'XML External Entity (XXE)'),
            ('idor', 'Insecure Direct Object Reference')
        ]
        
      
        checkbox_frame = ttk.Frame(frame)
        checkbox_frame.grid(column=0, row=2, columnspan=2, sticky='w', padx=10, pady=5)
        
        for i, (test_id, test_name) in enumerate(tests):
            var = tk.BooleanVar(value=True)
            self.test_vars[test_id] = var
            
            
            cb_frame = ttk.Frame(checkbox_frame)
            cb_frame.grid(column=0 if i < 6 else 1, row=i % 6, sticky='w', padx=5, pady=2)
            
            cb = ttk.Checkbutton(cb_frame, text=test_name, variable=var)
            cb.pack(side='left')
        
       
        self.btn_web_scan = ttk.Button(frame, text="Start Web Vulnerability Scan", command=self.start_web_scan)
        self.btn_web_scan.grid(column=0, row=8, columnspan=2, pady=10)
    
    @error_handler.protect_process
    def start_web_scan(self):
        url = self.entry_web_url.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return
        
        selected_tests = [test_id for test_id, var in self.test_vars.items() if var.get()]
        
        if not selected_tests:
            messagebox.showerror("Error", "Please select at least one test to perform.")
            return
        
        url = normalize_url(url)
        self.app.log_message(f"[+] Starting web vulnerability scan on {url}")
        
        def scan():
            try:
                scanner = EliteWebVulnScanner(url)
                result = scanner.run_selected_checks(selected_tests)
                self.app.log_message(result)
                error_handler.reset_error_count()  
            except Exception as e:
                error_msg = f"[-] Web vulnerability scan error: {e}"
                self.app.log_message(error_msg)
                error_handler.handle_error(e, "web_vuln_scan")
        
        threading.Thread(target=scan, daemon=True).start()
