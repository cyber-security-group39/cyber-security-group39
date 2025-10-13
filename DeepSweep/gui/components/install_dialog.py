import tkinter as tk
from tkinter import ttk, messagebox
import threading

class InstallDialog:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.dialog = None
    
    def ask_install_tor(self):
  
        result = messagebox.askyesno(
            "Tor Not Installed",
            "Tor is not installed on your system.\n\n"
            "Would you like to install it automatically?\n\n"
            "This requires administrator privileges.",
            parent=self.parent
        )
        return result
    
    def show_install_progress(self):
        
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Installing Tor")
        self.dialog.geometry("300x150")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
      
        self.dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() - self.dialog.winfo_width()) // 2
        y = self.parent.winfo_y() + (self.parent.winfo_height() - self.dialog.winfo_height()) // 2
        self.dialog.geometry(f"+{x}+{y}")
        
    
        ttk.Label(self.dialog, text="Installing Tor...", font=("Arial", 12)).pack(pady=20)
        progress = ttk.Progressbar(self.dialog, mode='indeterminate')
        progress.pack(pady=10, padx=20, fill='x')
        progress.start()
        
        ttk.Label(self.dialog, text="This may take a few minutes", font=("Arial", 9)).pack(pady=5)
        
        return self.dialog
    
    def close_dialog(self):
       
        if self.dialog:
            self.dialog.grab_release()
            self.dialog.destroy()
            self.dialog = None
