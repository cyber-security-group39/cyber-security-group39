import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import traceback
from error_handler import error_handler

class OutputConsole:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.create_widgets()
    
    def create_widgets(self):
  
        console_frame = ttk.Frame(self.parent)
        console_frame.pack(fill='both', expand=True, pady=10)
        
        ttk.Label(console_frame, text="Scan Results:", font=("Courier New", 12, "bold")).pack(anchor='w', pady=5)
        
       
        text_frame = ttk.Frame(console_frame)
        text_frame.pack(fill='both', expand=True)
        
        self.text_output = scrolledtext.ScrolledText(
            text_frame, 
            width=100, 
            height=20,
            bg='#000000',
            fg='#00FF00',
            font=("Courier New", 10),
            insertbackground='#00FF00'
        )
        self.text_output.pack(fill='both', expand=True)
        
        
        button_frame = ttk.Frame(console_frame)
        button_frame.pack(fill='x', pady=5)
        
        ttk.Button(button_frame, text="Clear Output", command=self.clear_output).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save Results", command=self.save_results).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Export Report", command=self.export_report).pack(side='left', padx=5)
        ttk.Button(button_frame, text="View Error Log", command=self.view_error_log).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Emergency Stop", command=self.emergency_stop).pack(side='right', padx=5)
    
    def log_message(self, message):
        self.text_output.insert(tk.END, message + "\n")
        self.text_output.see(tk.END)
        self.parent.update_idletasks()
    
    def clear_output(self):
        self.text_output.delete(1.0, tk.END)
    
    def save_results(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.text_output.get(1.0, tk.END))
                self.log_message(f"[+] Results saved to {filename}")
            except Exception as e:
                self.log_message(f"[-] Error saving results: {e}")
    
    def export_report(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        if filename:
            try:
                from datetime import datetime
                content = self.text_output.get(1.0, tk.END)
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Vulnerability Scan Report</title>
                    <style>
                        body {{ background-color: #121212; color: #00FF00; font-family: 'Courier New', monospace; }}
                        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
                        .vuln {{ color: #FF0000; font-weight: bold; }}
                    </style>
                </head>
                <body>
                    <h1>Vulnerability Scan Report</h1>
                    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <pre>{content}</pre>
                </body>
                </html>
                """
                with open(filename, 'w') as f:
                    f.write(html_content)
                self.log_message(f"[+] Report exported to {filename}")
            except Exception as e:
                self.log_message(f"[-] Error exporting report: {e}")
    
    def view_error_log(self):
        """Display the error log in a new window"""
        error_window = tk.Toplevel(self.parent)
        error_window.title("Error Log")
        error_window.geometry("800x600")
        error_window.configure(bg='#121212')
        
        error_text = scrolledtext.ScrolledText(
            error_window,
            bg='#000000',
            fg='#00FF00',
            font=("Courier New", 10)
        )
        error_text.pack(fill='both', expand=True, padx=10, pady=10)
        
      
        error_summary = error_handler.get_error_summary()
        error_text.insert(tk.END, f"Error Summary:\n")
        error_text.insert(tk.END, f"Total Errors: {error_summary['total_errors']}\n")
        error_text.insert(tk.END, f"Critical Errors: {error_summary['critical_errors']}\n\n")
        
       
        if error_summary['recent_errors']:
            error_text.insert(tk.END, "Recent Errors:\n")
            for error in error_summary['recent_errors']:
                error_text.insert(tk.END, f"Time: {error['timestamp']}\n")
                error_text.insert(tk.END, f"Context: {error['context']}\n")
                error_text.insert(tk.END, f"Error: {error['error_type']}: {error['error_message']}\n")
                error_text.insert(tk.END, f"Traceback:\n{error['traceback']}\n")
                error_text.insert(tk.END, "-" * 50 + "\n")
        else:
            error_text.insert(tk.END, "No recent errors recorded.\n")
        
        error_text.config(state=tk.DISABLED)
    
    def emergency_stop(self):
        
        if messagebox.askyesno("Emergency Stop", "Are you sure you want to stop all scanning activities?"):
            self.log_message("[!] EMERGENCY STOP INITIATED - Terminating all scans")
            self.log_message("[!] All scanning threads terminated")
