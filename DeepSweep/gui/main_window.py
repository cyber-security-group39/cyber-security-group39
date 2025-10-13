import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


try:
 
    from gui.components.output_console import OutputConsole
    from gui.components.banner import create_banner
    from gui.components.install_dialog import InstallDialog
    from gui.tabs.port_scanner_tab import PortScannerTab
    from gui.tabs.device_discovery_tab import DeviceDiscoveryTab
    from gui.tabs.web_scanner_tab import WebScannerTab
except ImportError:
   
    try:
        from .components.output_console import OutputConsole
        from .components.banner import create_banner
        from .components.install_dialog import InstallDialog
        from .tabs.port_scanner_tab import PortScannerTab
        from .tabs.device_discovery_tab import DeviceDiscoveryTab
        from .tabs.web_scanner_tab import WebScannerTab
    except ImportError as e:
        print(f"Import error: {e}")
        print("Please make sure all component files exist")
        sys.exit(1)

from config.theme import BG_COLOR, FG_COLOR, ACCENT_COLOR, BUTTON_COLOR, TEXT_BG, CHECKBOX_BG, FONT, LARGE_FONT
from error_handler import error_handler
from tor_manager import tor_manager

class EliteVulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DEEPSWEEP Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG_COLOR)
        
       
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
      
        create_banner(root)
        
      
        self.install_dialog = InstallDialog(root, self)
        
        self.create_widgets()
        
        
        self.monitor_errors()
        
       
        self.monitor_ip()
        
    def configure_styles(self):
        self.style.configure('TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=FONT)
        self.style.configure('TButton', background=BUTTON_COLOR, foreground=FG_COLOR, font=FONT)
        self.style.configure('TCheckbutton', background=CHECKBOX_BG, foreground=FG_COLOR, font=FONT)
        self.style.configure('TNotebook', background=BG_COLOR)
        self.style.configure('TNotebook.Tab', background=BUTTON_COLOR, foreground=FG_COLOR, font=FONT)
        self.style.configure('TEntry', fieldbackground=TEXT_BG, foreground=FG_COLOR, font=FONT)
        self.style.configure('Red.TLabel', background=BG_COLOR, foreground='red', font=FONT)
        self.style.configure('Green.TLabel', background=BG_COLOR, foreground='green', font=FONT)
        
    def monitor_errors(self):
     
        error_summary = error_handler.get_error_summary()
        if error_summary['total_errors'] > 0:
            status_text = f"Errors: {error_summary['total_errors']} | Critical: {error_summary['critical_errors']}"
            if hasattr(self, 'status_label'):
                self.status_label.config(text=status_text)
        
      
        self.root.after(5000, self.monitor_errors)
    
    def monitor_ip(self):
  
        def check_ip():
            try:
                
                ip_info = tor_manager.get_detailed_ip_info()
                ip_address = ip_info['ip']
                status = ip_info['status']
                is_tor = ip_info['is_tor']
                
                if hasattr(self, 'ip_label'):
                    display_text = f"Current IP: {ip_address} ({status})"
                    self.ip_label.config(text=display_text)
                    
                  
                    if is_tor:
                        self.ip_label.configure(style='Green.TLabel')
                    else:
                        self.ip_label.configure(style='Red.TLabel')
                        
            except Exception as e:
                if hasattr(self, 'ip_label'):
                    self.ip_label.config(text="Current IP: Unable to determine")
                    self.ip_label.configure(style='Red.TLabel')
        
       
        threading.Thread(target=check_ip, daemon=True).start()
        
       
        self.root.after(30000, self.monitor_ip)
        
    def create_widgets(self):
       
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
       
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', pady=5)
        
      
        self.ip_label = ttk.Label(
            top_frame, 
            text="Current IP: Checking...",
            style='Red.TLabel'
        )
        self.ip_label.pack(side='left', padx=10)
        
        
        self.create_anonymity_button(top_frame)
        
       
        refresh_btn = ttk.Button(
            top_frame,
            text="Refresh IP",
            command=self.monitor_ip
        )
        refresh_btn.pack(side='right', padx=10)
        
       
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill='x', pady=5)
        
        self.status_label = ttk.Label(
            status_frame, 
            text="Ready", 
            font=("Courier New", 8),
            foreground=ACCENT_COLOR
        )
        self.status_label.pack(side='left')
        
        
        tab_control = ttk.Notebook(main_frame)
        
       
        self.port_scanner_tab = PortScannerTab(tab_control, self)
        self.device_discovery_tab = DeviceDiscoveryTab(tab_control, self)
        self.web_scanner_tab = WebScannerTab(tab_control, self)
        
        tab_control.add(self.port_scanner_tab.frame, text='Port Scanner')
        tab_control.add(self.device_discovery_tab.frame, text='Network Discovery')
        tab_control.add(self.web_scanner_tab.frame, text='Web Application Scanner')
        
        
        self.output_console = OutputConsole(main_frame, self)
        
        tab_control.pack(expand=1, fill='both')
    
    def create_anonymity_button(self, parent):
      
        anonymity_frame = ttk.Frame(parent)
        anonymity_frame.pack(side='right', padx=10)
        
        self.anonymity_var = tk.BooleanVar(value=False)
        self.anonymity_btn = ttk.Checkbutton(
            anonymity_frame, 
            text="Be Anonymous (Use Tor)", 
            variable=self.anonymity_var,
            command=self.toggle_anonymity,
            style='TCheckbutton'
        )
        self.anonymity_btn.pack(side='left', padx=5)
        
     
        self.anonymity_status = ttk.Label(
            anonymity_frame, 
            text="Disabled", 
            foreground="red"
        )
        self.anonymity_status.pack(side='left', padx=5)
    
    def toggle_anonymity(self):
        
        if self.anonymity_var.get():
            
            self.log_message("[+] Attempting to enable Tor anonymity...")
            self.anonymity_status.config(text="Enabling...", foreground="orange")
            
       
            def enable_tor():
             
                if not tor_manager.is_tor_installed():
                   
                    if self.install_dialog.ask_install_tor():
                        progress_dialog = self.install_dialog.show_install_progress()
                        
                        try:
                            if tor_manager.start_tor(auto_install=True):
                                self.anonymity_status.config(text="Enabled", foreground="green")
                                self.log_message("[+] Tor installed and started successfully!")
                                
                                self.monitor_ip()
                            else:
                                self.anonymity_var.set(False)
                                self.anonymity_status.config(text="Failed", foreground="red")
                                self.log_message("[-] Failed to install or start Tor.")
                        finally:
                            self.install_dialog.close_dialog()
                    else:
                        self.anonymity_var.set(False)
                        self.anonymity_status.config(text="Disabled", foreground="red")
                        self.log_message("[-] Tor installation cancelled.")
                else:
              
                    if tor_manager.start_tor():
                        self.anonymity_status.config(text="Enabled", foreground="green")
                        self.log_message("[+] Tor anonymity enabled")
                        
                        self.monitor_ip()
                    else:
                        self.anonymity_var.set(False)
                        self.anonymity_status.config(text="Failed", foreground="red")
                        self.log_message("[-] Failed to start Tor.")
            
            threading.Thread(target=enable_tor, daemon=True).start()
        else:
           
            self.log_message("[+] Disabling Tor anonymity...")
            self.anonymity_status.config(text="Disabling...", foreground="orange")
            
           
            def disable_tor():
                if tor_manager.stop_tor():
                    self.anonymity_status.config(text="Disabled", foreground="red")
                    self.log_message("[+] Tor anonymity disabled")
                    
                    self.monitor_ip()
                else:
                    self.log_message("[-] Error disabling Tor")
            
            threading.Thread(target=disable_tor, daemon=True).start()
    
    def log_message(self, message):
        self.output_console.log_message(message)
    
    def clear_output(self):
        self.output_console.clear_output()
    
    def save_results(self):
        self.output_console.save_results()
    
    def export_report(self):
        self.output_console.export_report()
    
    def view_error_log(self):
        self.output_console.view_error_log()
    
    def emergency_stop(self):
        self.output_console.emergency_stop()
