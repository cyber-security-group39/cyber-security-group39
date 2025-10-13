import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from scanners.port_scanner import ElitePortScanner
from utils.validation_utils import is_valid_ip
from error_handler import error_handler
import threading

class PortScannerTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.create_widgets()
    
    def create_widgets(self):
        frame = self.frame
        
        # Target input
        ttk.Label(frame, text="Target IP/Hostname:").grid(column=0, row=0, sticky='w', padx=10, pady=5)
        self.entry_port_target = ttk.Entry(frame, width=30)
        self.entry_port_target.grid(column=1, row=0, padx=10, pady=5)
        
        # Port range
        ttk.Label(frame, text="Ports (e.g. 1-1000 or 80,443,8080):").grid(column=0, row=1, sticky='w', padx=10, pady=5)
        self.entry_ports = ttk.Entry(frame, width=30)
        self.entry_ports.grid(column=1, row=1, padx=10, pady=5)
        self.entry_ports.insert(0, "1-1000")
        
        # Threads
        ttk.Label(frame, text="Threads:").grid(column=0, row=2, sticky='w', padx=10, pady=5)
        self.entry_threads = ttk.Entry(frame, width=10)
        self.entry_threads.grid(column=1, row=2, sticky='w', padx=10, pady=5)
        self.entry_threads.insert(0, "100")
        
        # Scan type
        ttk.Label(frame, text="Scan Type:").grid(column=0, row=3, sticky='w', padx=10, pady=5)
        self.scan_type = ttk.Combobox(frame, values=['connect', 'syn', 'udp'], width=10)
        self.scan_type.grid(column=1, row=3, sticky='w', padx=10, pady=5)
        self.scan_type.set('connect')
        
        # Scan button
        self.btn_port_scan = ttk.Button(frame, text="Start Port Scan", command=self.start_port_scan)
        self.btn_port_scan.grid(column=0, row=4, columnspan=2, pady=10)
    
    @error_handler.protect_process
    def start_port_scan(self):
        target = self.entry_port_target.get().strip()
        ports = self.entry_ports.get().strip()
        threads = self.entry_threads.get().strip()
        scan_type = self.scan_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return
        
        if not ports:
            messagebox.showerror("Error", "Please enter port(s) to scan.")
            return
        
        if not threads.isdigit() or int(threads) <= 0:
            messagebox.showerror("Error", "Please enter a valid number of threads.")
            return
        
        self.app.log_message(f"[+] Starting {scan_type} scan on {target}")
        self.app.log_message(f"[+] Ports: {ports}, Threads: {threads}")
        
        def scan():
            try:
                scanner = ElitePortScanner(target, ports, int(threads), scan_type)
                result = scanner.scan()
                self.app.log_message(result)
                error_handler.reset_error_count() 
            except Exception as e:
                error_msg = f"[-] Port scan error: {e}"
                self.app.log_message(error_msg)
                error_handler.handle_error(e, "port_scan")
        
        threading.Thread(target=scan, daemon=True).start()
