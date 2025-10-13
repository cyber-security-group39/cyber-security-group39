import tkinter as tk
from tkinter import ttk, messagebox
from scanners.device_discovery import EliteDeviceDiscovery
from utils.validation_utils import is_valid_ip_range
from error_handler import error_handler
import threading

class DeviceDiscoveryTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = ttk.Frame(parent)
        self.create_widgets()
    
    def create_widgets(self):
        frame = self.frame
        
       
        ttk.Label(frame, text="IP Range (CIDR notation):").grid(column=0, row=0, sticky='w', padx=10, pady=5)
        self.entry_ip_range = ttk.Entry(frame, width=30)
        self.entry_ip_range.grid(column=1, row=0, padx=10, pady=5)
        self.entry_ip_range.insert(0, "192.168.1.0/24")
        
        
        self.btn_discover = ttk.Button(frame, text="Discover Devices", command=self.start_device_discovery)
        self.btn_discover.grid(column=0, row=1, columnspan=2, pady=10)
        
    
        ttk.Label(frame, text="* Network discovery requires appropriate permissions *", font=("Courier New", 8)).grid(column=0, row=2, columnspan=2, sticky='w', padx=10, pady=5)
    
    @error_handler.protect_process
    def start_device_discovery(self):
        ip_range = self.entry_ip_range.get().strip()
        
        if not is_valid_ip_range(ip_range):
            messagebox.showerror("Error", "Please enter a valid IP range in CIDR notation (e.g. 192.168.1.0/24).")
            return
        
        self.app.log_message(f"[+] Starting network discovery on {ip_range}")
        
        def discover():
            try:
                discovery = EliteDeviceDiscovery(ip_range)
                result = discovery.ping_sweep()
                self.app.log_message(result)
                error_handler.reset_error_count()  
            except Exception as e:
                error_msg = f"[-] Network discovery error: {e}"
                self.app.log_message(error_msg)
                error_handler.handle_error(e, "device_discovery")
        
        threading.Thread(target=discover, daemon=True).start()
