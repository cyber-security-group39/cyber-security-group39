import tkinter as tk
from tkinter import ttk
from pyfiglet import Figlet
from config.theme import BG_COLOR, FG_COLOR

def create_banner(parent):
    """Create the application banner"""
  
    banner_frame = ttk.Frame(parent)
    banner_frame.pack(fill='x', pady=5)
    
    
    f = Figlet(font='slant')
    banner_text = f.renderText('DEEPSWEEP')
    banner_text += "Developed by Nix".center(80)
    
  
    banner_label = ttk.Label(
        banner_frame, 
        text=banner_text,
        font=("Courier New", 8),
        justify='center',
        background=BG_COLOR,
        foreground=FG_COLOR
    )
    banner_label.pack()
