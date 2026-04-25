import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image, ImageTk, ImageDraw
import os
import secrets
import threading
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import struct
import shutil
import numpy as np
from tkinter import filedialog, messagebox


# Import modules
from auth_system import AuthSystem
from lsb_engine import encode_lsb, decode_lsb
from crypto_utils import encrypt_message, decrypt_message
from security_analysis import SecurityAnalyzer


from detector import detect_stego
from analyzer import analyze_image
from extractor import forensic_extract
from integrity import compute_hash
from case_manager import create_case, add_evidence
from reporter import generate_report


forensic_image_path = None




def run_forensic_analysis(self):
    if not hasattr(self, "forensic_image_path"):
        messagebox.showerror("Error", "Please select an image first")
        return

    try:
        case_id, case_path = create_case("gui_case")
        evidence_path = add_evidence(case_path, self.forensic_image_path)

        file_hash = compute_hash(evidence_path)
        is_stego, ratio = detect_stego(evidence_path)
        analysis = analyze_image(evidence_path)
        extraction = forensic_extract(evidence_path)

        result_text = f"""
=== FORENSIC RESULTS ===

Hash: {file_hash}
Stego Detected: {is_stego}
LSB Ratio: {ratio:.4f}
Entropy: {analysis['entropy']:.4f}

Extracted Data:
{extraction.get('data', 'None')}
"""

        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, result_text)

        findings = {
            "Hash": file_hash,
            "Stego Detected": is_stego,
            "LSB Ratio": ratio,
            "Entropy": analysis["entropy"],
            "Extracted Data": extraction.get("data", "None")
        }

        report_path = generate_report(case_id, findings)

        messagebox.showinfo("Success", f"Report saved at:\n{report_path}")

    except Exception as e:
        messagebox.showerror("Error", str(e))



# --- PREMIUM THEME ---
COLORS = {
    # Base Colors
    "bg": "#0a0e27",              # Deep Blue-Black Background
    "bg_secondary": "#1a1f3a",    # Secondary Background
    "fg": "#e8eaf6",              # Primary Text - Light
    "fg_secondary": "#b8bcc8",    # Secondary Text
    
    # Surface & Cards
    "header_bg": "#0d1128",       # Header Dark
    "card_bg": "#1e2139",         # Card Background
    "card_hover": "#252847",      # Card Hover State
    "input_bg": "#2a2f4a",        # Input Fields
    "input_focus": "#333859",     # Input Focus
    
    # Accents & Highlights
    "accent": "#6c63ff",          # Primary Purple
    "accent_hover": "#8178ff",    # Accent Hover
    "accent_light": "#9d97ff",    # Light Accent
    "accent_glow": "#4a42b8",     # Glow Effect (darker purple)
    
    # Semantic Colors
    "success": "#00f2b8",         # Cyan-Green Success
    "success_glow": "#00b890",    # Success Glow (darker)
    "danger": "#ff6b9d",          # Pink-Red Danger
    "warning": "#ffd93d",         # Yellow Warning
    "info": "#4dd4ff",            # Sky Blue Info
    
    # Gradients & Effects
    "gradient_start": "#6c63ff",  # Gradient Start
    "gradient_end": "#4d7cfe",    # Gradient End
    "glass_overlay": "#2a2f4a",   # Glassmorphism Overlay
    "shadow_color": "#000000",    # Shadow
    "border": "#3d4263",          # Borders
    "border_light": "#4a5080",    # Light Borders
}

# --- CUSTOM WIDGETS ---
class CyberButton(tk.Frame):
    """Premium button with gradient, animations, and glow effects."""
    def __init__(self, parent, text, command, width=160, height=45, bg=None, fg="white", icon=None, **kwargs):
        super().__init__(parent, bg=parent['bg'] if isinstance(parent, dict) else parent.cget('bg'))
        self.command = command
        self.default_bg = bg or COLORS["accent"]
        self.hover_bg = COLORS["accent_hover"]
        self.fg = fg
        self.width = width
        self.height = height
        self.icon = icon
        self.is_hovered = False
        
        # Create canvas with glow layer support
        self.canvas = tk.Canvas(self, width=width+4, height=height+4, 
                               bg=parent['bg'] if isinstance(parent, dict) else parent.cget('bg'), 
                               highlightthickness=0)
        self.canvas.pack()
        
        # Shadow/Glow layer (initially hidden)
        self.r = 12
        self.glow = self.round_rect(2, 2, width+2, height+2, self.r+2, 
                                    fill=COLORS["accent_glow"], outline="")
        self.canvas.itemconfig(self.glow, state='hidden')
        
        # Main button
        self.rect = self.round_rect(2, 2, width+2, height+2, self.r, fill=self.default_bg, outline="")
        
        # Text with icon support
        text_display = f"{icon} {text}" if icon else text
        self.text_id = self.canvas.create_text(width/2+2, height/2+2, text=text_display, 
                                              fill=self.fg, font=("Segoe UI", 11, "bold"))
        
        self.canvas.bind("<Enter>", self.on_enter)
        self.canvas.bind("<Leave>", self.on_leave)
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<ButtonRelease-1>", self.on_release)
        
    def round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = (x1+r, y1, x1+r, y1, x2-r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y1+r, x2, y2-r, 
                 x2, y2-r, x2, y2, x2-r, y2, x2-r, y2, x1+r, y2, x1+r, y2, x1, y2, x1, y2-r, 
                 x1, y2-r, x1, y1+r, x1, y1+r, x1, y1)
        return self.canvas.create_polygon(points, **kwargs, smooth=True)

    def on_enter(self, e):
        self.is_hovered = True
        self.canvas.itemconfig(self.rect, fill=self.hover_bg)
        self.canvas.itemconfig(self.glow, state='normal')
        # Subtle lift effect
        self.canvas.move(self.rect, 0, -1)
        self.canvas.move(self.text_id, 0, -1)
        
    def on_leave(self, e):
        self.is_hovered = False
        self.canvas.itemconfig(self.rect, fill=self.default_bg)
        self.canvas.itemconfig(self.glow, state='hidden')
        # Reset position
        self.canvas.move(self.rect, 0, 1)
        self.canvas.move(self.text_id, 0, 1)
        
    def on_click(self, e):
        # Press effect
        self.canvas.move(self.rect, 0, 1)
        self.canvas.move(self.text_id, 0, 1)
        
    def on_release(self, e):
        # Release effect
        if self.is_hovered:
            self.canvas.move(self.rect, 0, -1)
            self.canvas.move(self.text_id, 0, -1)
        if self.command: 
            self.command()

class CyberEntry(tk.Frame):
    """Premium input field with focus animations and glow effects."""
    def __init__(self, parent, placeholder="", is_password=False, width=300):
        super().__init__(parent, bg=parent['bg'] if isinstance(parent, dict) else parent.cget('bg'))
        self.var = tk.StringVar()
        self.is_password = is_password
        self.placeholder = placeholder
        
        # Label
        self.label = tk.Label(self, text=placeholder, bg=self.cget('bg'), 
                             fg=COLORS["accent"], font=("Segoe UI", 9, "bold"))
        self.label.pack(anchor="w", pady=(0, 4))
        
        # Container with border for focus effect
        self.container = tk.Frame(self, bg=COLORS["input_bg"], bd=2, relief="flat")
        self.container.pack(fill="x")
        
        # Inner frame for padding
        inner = tk.Frame(self.container, bg=COLORS["input_bg"])
        inner.pack(fill="both", expand=True, padx=10, pady=8)
        
        # Entry field
        self.entry = tk.Entry(inner, textvariable=self.var, bg=COLORS["input_bg"], fg=COLORS["fg"], 
                              insertbackground=COLORS["accent"], relief="flat", 
                              font=("Segoe UI", 11), bd=0)
        if is_password: 
            self.entry.config(show="●")
        self.entry.pack(side="left", fill="x", expand=True)
        
        # Password toggle
        if is_password:
            self.eye = tk.Label(inner, text="👁", bg=COLORS["input_bg"], 
                               fg=COLORS["fg_secondary"], cursor="hand2", font=("Segoe UI", 12))
            self.eye.pack(side="right", padx=(8, 0))
            self.eye.bind("<Button-1>", self.toggle)
            self.visible = False
        
        # Bind focus events for glow effect
        self.entry.bind("<FocusIn>", self.on_focus)
        self.entry.bind("<FocusOut>", self.on_blur)
            
    def on_focus(self, e):
        """Show focus glow effect"""
        self.container.config(bg=COLORS["accent"], bd=2)
        self.label.config(fg=COLORS["accent_light"])
        
    def on_blur(self, e):
        """Remove focus glow"""
        self.container.config(bg=COLORS["border"], bd=2)
        self.label.config(fg=COLORS["accent"])
        
    def toggle(self, e):
        self.visible = not self.visible
        self.entry.config(show="" if self.visible else "●")
        self.eye.config(fg=COLORS["accent"] if self.visible else COLORS["fg_secondary"])

    def get(self): 
        return self.var.get()
    
    def set(self, t): 
        self.var.set(t)

# --- APP ---
class StegoApp:
    def __init__(self):
        try: self.root = TkinterDnD.Tk()
        except: self.root = tk.Tk()
        self.root.title("SecureStego Pro • Advanced Steganography Security Suite")
        self.root.geometry("1200x800")
        self.root.configure(bg=COLORS["bg"])
        
        self.auth = AuthSystem()
        self.security = SecurityAnalyzer()
        
        # Initialize Styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Horizontal.TProgressbar", foreground=COLORS["accent"], background=COLORS["accent"], troughcolor=COLORS["input_bg"], borderwidth=0)
        
        if not self.auth.current_user:
            self.show_login()
        else:
            self.show_main()
            
        self.root.mainloop()

    def show_login(self):
        for w in self.root.winfo_children(): w.destroy()
        
        # Background
        bg_frame = tk.Frame(self.root, bg=COLORS["bg"])
        bg_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Center container
        p = tk.Frame(self.root, bg=COLORS["bg"])
        p.place(relx=0.5, rely=0.5, anchor="center")
        
        # Header with gradient accent
        header_frame = tk.Frame(p, bg=COLORS["bg"])
        header_frame.pack(pady=(0, 24))
        
        # Logo/Icon placeholder (using Unicode)
        tk.Label(header_frame, text="🔒", font=("Segoe UI", 48), 
                bg=COLORS["bg"], fg=COLORS["accent"]).pack()
        
        tk.Label(header_frame, text="SECURE STEGO PRO", 
                font=("Segoe UI", 32, "bold"), bg=COLORS["bg"], 
                fg=COLORS["fg"]).pack()
        
        tk.Label(header_frame, text="Advanced Steganography Security Suite", 
                font=("Segoe UI", 11), bg=COLORS["bg"], 
                fg=COLORS["fg_secondary"]).pack(pady=(4, 0))
        
        # Glassmorphism card
        card = tk.Frame(p, bg=COLORS["card_bg"], bd=1, relief="solid")
        card.config(highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack()
        
        # Inner padding
        card_inner = tk.Frame(card, bg=COLORS["card_bg"])
        card_inner.pack(padx=48, pady=40)
        
        tk.Label(card_inner, text="Sign In", font=("Segoe UI", 20, "bold"), 
                bg=COLORS["card_bg"], fg=COLORS["fg"]).pack(pady=(0, 24))
        
        # Inputs
        self.l_user = CyberEntry(card_inner, "USERNAME", width=280)
        self.l_user.pack(pady=8)
        
        self.l_pass = CyberEntry(card_inner, "PASSWORD", True, width=280)
        self.l_pass.pack(pady=8)
        
        # Login button with icon
        CyberButton(card_inner, "LOGIN", self.do_login, width=280, icon="⚡").pack(pady=(24, 16))
        
        # Divider
        divider = tk.Frame(card_inner, bg=COLORS["border"], height=1)
        divider.pack(fill="x", pady=16)
        
        # Sign up link
        signup_frame = tk.Frame(card_inner, bg=COLORS["card_bg"])
        signup_frame.pack()
        
        tk.Label(signup_frame, text="Don't have an account?  ", 
                fg=COLORS["fg_secondary"], bg=COLORS["card_bg"], 
                font=("Segoe UI", 10)).pack(side="left")
        
        lbl = tk.Label(signup_frame, text="Create Account", 
                      fg=COLORS["accent"], bg=COLORS["card_bg"], 
                      cursor="hand2", font=("Segoe UI", 10, "bold"))
        lbl.pack(side="left")
        lbl.bind("<Button-1>", lambda e: self.show_signup())
        
        # Hover effect for link
        lbl.bind("<Enter>", lambda e: lbl.config(fg=COLORS["accent_light"]))
        lbl.bind("<Leave>", lambda e: lbl.config(fg=COLORS["accent"]))

    def show_signup(self):
        for w in self.root.winfo_children(): w.destroy()
        
        # Background
        bg_frame = tk.Frame(self.root, bg=COLORS["bg"])
        bg_frame.place(x=0, y=0, relwidth=1, relheight=1)
        
        p = tk.Frame(self.root, bg=COLORS["bg"])
        p.place(relx=0.5, rely=0.5, anchor="center")
        
        # Glassmorphism card
        card = tk.Frame(p, bg=COLORS["card_bg"], bd=1, relief="solid")
        card.config(highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack()
        
        # Inner padding
        card_inner = tk.Frame(card, bg=COLORS["card_bg"])
        card_inner.pack(padx=48, pady=40)
        
        # Header
        tk.Label(card_inner, text="✨ Create Account", font=("Segoe UI", 24, "bold"), 
                bg=COLORS["card_bg"], fg=COLORS["fg"]).pack(pady=(0, 8))
        
        tk.Label(card_inner, text="Join SecureStego Pro", 
                font=("Segoe UI", 11), bg=COLORS["card_bg"], 
                fg=COLORS["fg_secondary"]).pack(pady=(0, 24))
        
        # Form fields
        self.s_u = CyberEntry(card_inner, "Username", width=320)
        self.s_u.pack(pady=6)
        
        self.s_p = CyberEntry(card_inner, "Password", True, width=320)
        self.s_p.pack(pady=6)
        
        self.s_k = CyberEntry(card_inner, "Fixed Password Key (Recovery)", True, width=320)
        self.s_k.pack(pady=6)
        
        self.s_a = CyberEntry(card_inner, "Security Answer (Pet Name)", width=320)
        self.s_a.pack(pady=6)
        
        # Register button
        CyberButton(card_inner, "CREATE ACCOUNT", self.do_signup, 
                   bg=COLORS["success"], width=320, icon="✓").pack(pady=(24, 16))
        
        # Divider
        divider = tk.Frame(card_inner, bg=COLORS["border"], height=1)
        divider.pack(fill="x", pady=12)
        
        # Back link
        back_frame = tk.Frame(card_inner, bg=COLORS["card_bg"])
        back_frame.pack()
        
        tk.Label(back_frame, text="Already have an account?  ", 
                fg=COLORS["fg_secondary"], bg=COLORS["card_bg"], 
                font=("Segoe UI", 10)).pack(side="left")
        
        lbl_back = tk.Label(back_frame, text="Sign In", 
                           fg=COLORS["accent"], bg=COLORS["card_bg"], 
                           cursor="hand2", font=("Segoe UI", 10, "bold"))
        lbl_back.pack(side="left")
        lbl_back.bind("<Button-1>", lambda e: self.show_login())
        
        # Hover effects
        lbl_back.bind("<Enter>", lambda e: lbl_back.config(fg=COLORS["accent_light"]))
        lbl_back.bind("<Leave>", lambda e: lbl_back.config(fg=COLORS["accent"]))

    def do_login(self):
        ok, msg = self.auth.signin(self.l_user.get(), self.l_pass.get())
        if ok: self.show_main()
        else: messagebox.showerror("Access Denied", msg)
        
    def do_signup(self):
        ok, msg = self.auth.signup(self.s_u.get(), self.s_p.get(), self.s_k.get(), "Pet Name?", self.s_a.get())
        if ok: 
            messagebox.showinfo("Success", "Account Created")
            self.show_login()
        else: messagebox.showerror("Error", msg)

    # --- MAIN INTERFACE ---
    def show_main(self):
        for w in self.root.winfo_children(): w.destroy()
        
        # Premium Sidebar
        bar = tk.Frame(self.root, bg=COLORS["header_bg"], width=260)
        bar.pack(side="left", fill="y")
        bar.pack_propagate(False)
        
        # Sidebar Header with accent
        header = tk.Frame(bar, bg=COLORS["accent"], height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        header_content = tk.Frame(header, bg=COLORS["accent"])
        header_content.pack(expand=True)
        
        tk.Label(header_content, text="🔐", font=("Segoe UI", 28), 
                bg=COLORS["accent"], fg="white").pack()
        tk.Label(header_content, text="SecureStego", font=("Segoe UI", 18, "bold"), 
                bg=COLORS["accent"], fg="white").pack()
        
        # User info section
        user_section = tk.Frame(bar, bg=COLORS["header_bg"])
        user_section.pack(fill="x", pady=20, padx=16)
        
        tk.Label(user_section, text="👤", font=("Segoe UI", 24), 
                bg=COLORS["header_bg"], fg=COLORS["accent"]).pack()
        tk.Label(user_section, text=self.auth.current_user, 
                font=("Segoe UI", 12, "bold"), bg=COLORS["header_bg"], 
                fg=COLORS["fg"]).pack(pady=(4, 0))
        tk.Label(user_section, text="Premium User", 
                font=("Segoe UI", 9), bg=COLORS["header_bg"], 
                fg=COLORS["fg_secondary"]).pack()
        
        # Navigation divider
        tk.Frame(bar, bg=COLORS["border"], height=1).pack(fill="x", padx=16, pady=8)
        
        # Main content area
        self.main_area = tk.Frame(self.root, bg=COLORS["bg"])
        self.main_area.pack(side="left", fill="both", expand=True, padx=24, pady=24)
        
        # Navigation Buttons with icons
        nav_items = [
            ("📊 Dashboard", self.page_dash),
            ("🔒 Encryption", self.page_enc),
            ("🔓 Decryption", self.page_dec),
            ("📜 History", self.page_hist),
            ("📈 Analytics", self.page_ana),
            ("🕵️Forensics", self.page_forensic)
        ]
        
        for txt, cmd in nav_items:
            btn = tk.Button(bar, text=txt, bg=COLORS["header_bg"], fg=COLORS["fg"], 
                          bd=0, font=("Segoe UI", 12), anchor="w", padx=20,
                          activebackground=COLORS["card_bg"], 
                          activeforeground=COLORS["accent"], command=cmd,
                          cursor="hand2")
            btn.pack(fill="x", ipady=14)
            
            # Hover effects
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=COLORS["card_bg"], fg=COLORS["accent"]))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=COLORS["header_bg"], fg=COLORS["fg"]))
            
        # Spacer
        tk.Frame(bar, bg=COLORS["header_bg"]).pack(fill="both", expand=True)
        
        # Sign out button
        signout_btn = tk.Button(bar, text="🚪 Sign Out", bg=COLORS["danger"], 
                               fg="white", bd=0, font=("Segoe UI", 11, "bold"),
                               command=self.show_login, cursor="hand2")
        signout_btn.pack(side="bottom", fill="x", ipady=16)
        signout_btn.bind("<Enter>", lambda e: signout_btn.config(bg=COLORS["accent"]))
        signout_btn.bind("<Leave>", lambda e: signout_btn.config(bg=COLORS["danger"]))
        
        self.page_dash()

    def clear_main(self):
        for w in self.main_area.winfo_children(): w.destroy()

    def page_dash(self):
        self.clear_main()
        
        # Welcome header
        header = tk.Frame(self.main_area, bg=COLORS["bg"])
        header.pack(fill="x", pady=(0, 32))
        
        tk.Label(header, text=f"Welcome back, {self.auth.current_user} 👋", 
                font=("Segoe UI", 28, "bold"), bg=COLORS["bg"], 
                fg=COLORS["fg"]).pack(anchor="w")
        
        tk.Label(header, text="Your personal steganography security dashboard", 
                font=("Segoe UI", 12), bg=COLORS["bg"], 
                fg=COLORS["fg_secondary"]).pack(anchor="w", pady=(4, 0))
        
        # Stats grid
        grid = tk.Frame(self.main_area, bg=COLORS["bg"])
        grid.pack(fill="x", pady=20)
        
        hist, _ = self.auth.get_encryption_history()
        
        # Calculate security level based on activity
        encryption_count = len(hist)
        if encryption_count == 0:
            security_level = "Getting Started"
            level_color = COLORS["info"]
        elif encryption_count < 5:
            security_level = "Basic"
            level_color = COLORS["warning"]
        elif encryption_count < 15:
            security_level = "Standard"
            level_color = COLORS["accent"]
        elif encryption_count < 30:
            security_level = "Advanced"
            level_color = COLORS["success"]
        else:
            security_level = "Expert"
            level_color = COLORS["success"]
        
        # Premium Stats Cards with icons
        self.stat_card_premium(grid, "Total Encryptions", str(encryption_count), 
                               COLORS["accent"], "🔢")
        self.stat_card_premium(grid, "Security Level", security_level, 
                               level_color, "🛡")
        self.stat_card_premium(grid, "Last Activity", 
                               hist[-1]['timestamp'][:10] if hist else "Never", 
                               COLORS["info"], "⏰")
        
        # Quick actions section
        actions_header = tk.Frame(self.main_area, bg=COLORS["bg"])
        actions_header.pack(fill="x", pady=(32, 16))
        
        tk.Label(actions_header, text="Quick Actions", 
                font=("Segoe UI", 18, "bold"), bg=COLORS["bg"], 
                fg=COLORS["fg"]).pack(anchor="w")
        
        # Quick action buttons
        actions_grid = tk.Frame(self.main_area, bg=COLORS["bg"])
        actions_grid.pack(fill="x")
        
        actions = [
            ("🔐 New Encryption", self.page_enc, COLORS["accent"]),
            ("🔓 Decrypt Message", self.page_dec, COLORS["info"]),
            ("📊 View Analytics", self.page_ana, COLORS["warning"])
        ]
        
        for text, cmd, color in actions:
            btn_frame = tk.Frame(actions_grid, bg=COLORS["bg"])
            btn_frame.pack(side="left", padx=(0, 16))
            CyberButton(btn_frame, text, cmd, width=200, height=50, bg=color).pack()

    def stat_card_premium(self, parent, title, val, col, icon):
        """Premium stat card with gradient accent and icon"""
        f = tk.Frame(parent, bg=COLORS["card_bg"], width=220, height=140, 
                    highlightbackground=COLORS["border"], highlightthickness=1)
        f.pack(side="left", fill="both", expand=True, padx=8)
        f.pack_propagate(False)
        
        # Gradient accent bar
        accent_bar = tk.Frame(f, bg=col, height=5)
        accent_bar.pack(fill="x")
        
        # Content area
        content = tk.Frame(f, bg=COLORS["card_bg"])
        content.pack(fill="both", expand=True, padx=20, pady=16)
        
        # Icon
        tk.Label(content, text=icon, font=("Segoe UI", 32), 
                bg=COLORS["card_bg"], fg=col).pack(anchor="w")
        
        # Value
        tk.Label(content, text=val, font=("Segoe UI", 24, "bold"), 
                bg=COLORS["card_bg"], fg=COLORS["fg"]).pack(anchor="w", pady=(8, 4))
        
        # Title
        tk.Label(content, text=title, font=("Segoe UI", 10), 
                bg=COLORS["card_bg"], fg=COLORS["fg_secondary"]).pack(anchor="w")
        
        # Hover effect
        def on_enter(e):
            f.config(bg=COLORS["card_hover"])
            content.config(bg=COLORS["card_hover"])
            for child in content.winfo_children():
                if isinstance(child, tk.Label) and child.cget('text') != icon:
                    child.config(bg=COLORS["card_hover"])
                    
        def on_leave(e):
            f.config(bg=COLORS["card_bg"])
            content.config(bg=COLORS["card_bg"])
            for child in content.winfo_children():
                if isinstance(child, tk.Label) and child.cget('text') != icon:
                    child.config(bg=COLORS["card_bg"])
        
        f.bind("<Enter>", on_enter)
        f.bind("<Leave>", on_leave)
        content.bind("<Enter>", on_enter)
        content.bind("<Leave>", on_leave)

    def page_hist(self):
        self.clear_main()
        tk.Label(self.main_area, text="Encryption History", font=("Segoe UI", 24), bg=COLORS["bg"], fg="white").pack(anchor="w", pady=(10,20))
        
        # Scrollable Canvas
        canvas = tk.Canvas(self.main_area, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.main_area, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLORS["bg"])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Populate with cards
        hist, _ = self.auth.get_encryption_history()
        for h in reversed(hist):  # Show newest first
            self.create_history_card(scrollable_frame, h)
    
    def create_history_card(self, parent, record):
        """Create a premium card for each history entry with image thumbnail"""
        card = tk.Frame(parent, bg=COLORS["card_bg"], bd=0, relief="solid",
                       highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="x", padx=16, pady=8)
        
        # Left side - Image thumbnail with premium frame
        img_frame = tk.Frame(card, bg=COLORS["input_bg"], width=130, height=110)
        img_frame.pack(side="left", padx=16, pady=12)
        img_frame.pack_propagate(False)
        
        # Try to load thumbnail
        img_path = record.get('image', '')
        if os.path.exists(img_path):
            try:
                img = Image.open(img_path)
                img.thumbnail((110, 90))
                photo = ImageTk.PhotoImage(img)
                img_label = tk.Label(img_frame, image=photo, bg=COLORS["input_bg"])
                img_label.image = photo  # Keep reference
                img_label.pack(expand=True)
            except:
                tk.Label(img_frame, text="🖼\nNo Preview", bg=COLORS["input_bg"], 
                        fg=COLORS["fg_secondary"], font=("Segoe UI", 10)).pack(expand=True)
        else:
            tk.Label(img_frame, text="📁\nNot Found", bg=COLORS["input_bg"], 
                    fg=COLORS["fg_secondary"], font=("Segoe UI", 10)).pack(expand=True)
        
        # Right side - Details
        details_frame = tk.Frame(card, bg=COLORS["card_bg"])
        details_frame.pack(side="left", fill="both", expand=True, padx=16, pady=12)
        
        # Header row
        header = tk.Frame(details_frame, bg=COLORS["card_bg"])
        header.pack(fill="x")
        
        tk.Label(header, text=os.path.basename(record.get('image', 'N/A')), 
                font=("Segoe UI", 13, "bold"), bg=COLORS["card_bg"], 
                fg=COLORS["fg"]).pack(side="left")
        
        status_color = COLORS["success"] if record.get('status') == 'Success' else COLORS["danger"]
        status_badge = tk.Label(header, text=f" {record.get('status', 'N/A')} ", 
                               font=("Segoe UI", 9, "bold"), bg=status_color, 
                               fg="white", padx=12, pady=4)
        status_badge.pack(side="right")
        
        # Info row 1
        time_frame = tk.Frame(details_frame, bg=COLORS["card_bg"])
        time_frame.pack(fill="x", pady=(8, 4))
        
        tk.Label(time_frame, text="🕒 ", font=("Segoe UI", 10), 
                bg=COLORS["card_bg"], fg=COLORS["accent"]).pack(side="left")
        tk.Label(time_frame, text=record['timestamp'], font=("Segoe UI", 10), 
                bg=COLORS["card_bg"], fg=COLORS["fg_secondary"]).pack(side="left")
        
        # Info row 2 - Sizes
        size_frame = tk.Frame(details_frame, bg=COLORS["card_bg"])
        size_frame.pack(fill="x", pady=2)
        
        info_text = f"📊 Original: {record.get('original_size', 0):,} B  •  Encrypted: {record.get('encrypted_size', 0):,} B"
        tk.Label(size_frame, text=info_text, font=("Segoe UI", 9), 
                bg=COLORS["card_bg"], fg=COLORS["fg_secondary"]).pack(anchor="w")
        
        # Info row 3 - Key
        key_frame = tk.Frame(details_frame, bg=COLORS["card_bg"])
        key_frame.pack(fill="x", pady=2)
        
        tk.Label(key_frame, text="🔑 ", font=("Segoe UI", 10), 
                bg=COLORS["card_bg"], fg=COLORS["warning"]).pack(side="left")
        tk.Label(key_frame, text=f"Key: {record.get('random_password', 'N/A')[:12]}...", 
                font=("Segoe UI", 9, "italic"), 
                bg=COLORS["card_bg"], fg=COLORS["fg_secondary"]).pack(side="left")
        
        # Hover effect
        def on_enter(e):
            card.config(bg=COLORS["card_hover"], highlightbackground=COLORS["accent"])
            details_frame.config(bg=COLORS["card_hover"])
            for child in [header, time_frame, size_frame, key_frame]:
                child.config(bg=COLORS["card_hover"])
                for lbl in child.winfo_children():
                    if isinstance(lbl, tk.Label) and lbl != status_badge:
                        lbl.config(bg=COLORS["card_hover"])
        
        def on_leave(e):
            card.config(bg=COLORS["card_bg"], highlightbackground=COLORS["border"])
            details_frame.config(bg=COLORS["card_bg"])
            for child in [header, time_frame, size_frame, key_frame]:
                child.config(bg=COLORS["card_bg"])
                for lbl in child.winfo_children():
                    if isinstance(lbl, tk.Label) and lbl != status_badge:
                        lbl.config(bg=COLORS["card_bg"])
        
        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)



    def page_enc(self):
        self.clear_main()
        
        # Page header
        tk.Label(self.main_area, text="🔒 Encryption", font=("Segoe UI", 24, "bold"), 
                bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor="w", pady=(0, 8))
        tk.Label(self.main_area, text="Hide secret messages or files within images", 
                font=("Segoe UI", 11), bg=COLORS["bg"], 
                fg=COLORS["fg_secondary"]).pack(anchor="w", pady=(0, 24))
        
        # Two Column Layout with premium cards
        row = tk.Frame(self.main_area, bg=COLORS["bg"])
        row.pack(fill="both", expand=True)
        
        # Left column - glassmorphism card
        col1 = tk.Frame(row, bg=COLORS["card_bg"], highlightbackground=COLORS["border"], 
                       highlightthickness=1)
        col1.pack(side="left", fill="both", expand=True, padx=(0,12))
        col1_inner = tk.Frame(col1, bg=COLORS["card_bg"])
        col1_inner.pack(padx=24, pady=24, fill="both", expand=True)
        
        # Col 1: Image & Data
        tk.Label(col1_inner, text="📷 Step 1: Source Image", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 13, "bold")).pack(anchor="w")
        
        self.enc_img_prev = tk.Label(col1_inner, text="🖼\n\nClick to select or drag image here", 
                                    bg=COLORS["input_bg"], fg=COLORS["fg_secondary"], 
                                    height=6, font=("Segoe UI", 11), cursor="hand2")
        self.enc_img_prev.pack(fill="x", pady=(12, 10))
        self.enc_img_prev.bind("<Button-1>", lambda e: self.enc_browse())
        
        CyberButton(col1_inner, "Browse Image", self.enc_browse, width=180, icon="📁").pack()
        
        tk.Label(col1_inner, text="💬 Step 2: Data to Hide", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(28, 8))
        
        # Mode Section with custom styling
        mode_fr = tk.Frame(col1_inner, bg=COLORS["card_bg"])
        mode_fr.pack(fill="x", pady=8)
        self.enc_mode = tk.StringVar(value="text")
        
        rb1 = tk.Radiobutton(mode_fr, text="📝 Text Message", variable=self.enc_mode, 
                            value="text", command=self.search_mode_switch, 
                            bg=COLORS["card_bg"], fg=COLORS["fg"], 
                            selectcolor=COLORS["accent"], activebackground=COLORS["card_bg"],
                            font=("Segoe UI", 10))
        rb1.pack(side="left", padx=(0, 20))
        
        rb2 = tk.Radiobutton(mode_fr, text="📄 File (PDF, Doc, etc.)", variable=self.enc_mode, 
                            value="file", command=self.search_mode_switch, 
                            bg=COLORS["card_bg"], fg=COLORS["fg"],
                            selectcolor=COLORS["accent"], activebackground=COLORS["card_bg"],
                            font=("Segoe UI", 10))
        rb2.pack(side="left")
        
        # Inputs Stack
        self.stack_fr = tk.Frame(col1_inner, bg=COLORS["card_bg"])
        self.stack_fr.pack(fill="x", pady=8)
        
        # Text Input
        self.fr_text = tk.Frame(self.stack_fr, bg=COLORS["card_bg"])
        self.enc_txt = scrolledtext.ScrolledText(self.fr_text, height=5, 
                                                 bg=COLORS["input_bg"], fg=COLORS["fg"], 
                                                 insertbackground=COLORS["accent"], bd=0,
                                                 font=("Segoe UI", 10))
        self.enc_txt.pack(fill="x")
        
        # File Input
        self.fr_file = tk.Frame(self.stack_fr, bg=COLORS["card_bg"])
        self.file_path_lbl = tk.Label(self.fr_file, text="No File Selected", 
                                     bg=COLORS["input_bg"], fg=COLORS["fg_secondary"], 
                                     height=2, font=("Segoe UI", 10))
        self.file_path_lbl.pack(fill="x", pady=8)
        CyberButton(self.fr_file, "Select File", self.browse_file_embed, 
                   width=140, icon="📎").pack()
        
        self.fr_text.pack(fill="x") # Default show text
        
        # Right column - glassmorphism card
        col2 = tk.Frame(row, bg=COLORS["card_bg"], highlightbackground=COLORS["border"], 
                       highlightthickness=1)
        col2.pack(side="left", fill="both", expand=True, padx=(12,0))
        col2_inner = tk.Frame(col2, bg=COLORS["card_bg"])
        col2_inner.pack(padx=24, pady=24, fill="both", expand=True)
        
        # Setup Col 2
        self.setup_enc_col2(col2_inner)
        
    def search_mode_switch(self):
        m = self.enc_mode.get()
        if m == "text":
            self.fr_file.pack_forget()
            self.fr_text.pack(fill="x")
        else:
            self.fr_text.pack_forget()
            self.fr_file.pack(fill="x")

    def browse_file_embed(self):
        f = filedialog.askopenfilename()
        if f: 
            self.embed_file_path = f
            self.file_path_lbl.config(text=os.path.basename(f), fg="white")
        
    def setup_enc_col2(self, col2):
        # Col 2: Security & Action
        tk.Label(col2, text="🔐 Step 3: Security", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 13, "bold")).pack(anchor="w")
        
        tk.Label(col2, text="Enter your encryption password to secure the data", 
                bg=COLORS["card_bg"], fg=COLORS["fg_secondary"], 
                font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 12))
        
        self.enc_pass = CyberEntry(col2, "Encryption Password", True, width=340)
        self.enc_pass.pack(fill="x", pady=8)
        
        # Progress bar
        tk.Label(col2, text="Progress:", bg=COLORS["card_bg"], 
                fg=COLORS["fg_secondary"], font=("Segoe UI", 9)).pack(anchor="w", pady=(20, 4))
        
        self.progress = ttk.Progressbar(col2, length=300, mode='determinate')
        self.progress.pack(fill="x", pady=8)
        
        # Encrypt button
        CyberButton(col2, "ENCRYPT & SAVE", self.enc_run, 
                   bg=COLORS["success"], width=340, height=50, icon="🔒").pack(pady=(20, 12))
        
        # Divider
        tk.Frame(col2, bg=COLORS["border"], height=1).pack(fill="x", pady=20)
        
        # Generated key section
        tk.Label(col2, text="🔑 Generated Recovery Key", bg=COLORS["card_bg"], 
                fg=COLORS["fg"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,4))
        
        tk.Label(col2, text="Save this key! You'll need it for decryption along with your password.", 
                bg=COLORS["card_bg"], fg=COLORS["warning"], 
                font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))
        
        gen_row = tk.Frame(col2, bg=COLORS["card_bg"])
        gen_row.pack(fill="x")
        
        self.enc_gen = CyberEntry(gen_row, "", width=260)
        self.enc_gen.pack(side="left", fill="x", expand=True)
        
        CyberButton(gen_row, "COPY", self.enc_copy, width=70, bg=COLORS["info"]).pack(side="right", padx=(8,0))
        
    def enc_copy(self):
        k = self.enc_gen.get()
        if k:
            self.root.clipboard_clear()
            self.root.clipboard_append(k)
            messagebox.showinfo("Copied", "Key copied to clipboard!")

    def page_dec(self):
        self.clear_main()
        
        # Page header - compact
        tk.Label(self.main_area, text="🔓 Decryption", font=("Segoe UI", 22, "bold"), 
                bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor="w", pady=(0, 4))
        tk.Label(self.main_area, text="Extract hidden data from steganographic images", 
                font=("Segoe UI", 10), bg=COLORS["bg"], 
                fg=COLORS["fg_secondary"]).pack(anchor="w", pady=(0, 16))
        
        # Simpler single card - no container
        card = tk.Frame(self.main_area, bg=COLORS["card_bg"], 
                       highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=60)
        
        card_inner = tk.Frame(card, bg=COLORS["card_bg"])
        card_inner.pack(padx=30, pady=20, fill="both", expand=True)
        
        # Image selection - compact
        tk.Label(card_inner, text="📷 Select Stego Image", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        
        CyberButton(card_inner, "Browse Image", self.dec_browse, 
                   width=300, icon="🖼").pack(anchor="w")
        
        self.dec_lbl = tk.Label(card_inner, text="No file selected", 
                               bg=COLORS["card_bg"], fg=COLORS["fg_secondary"],
                               font=("Segoe UI", 9))
        self.dec_lbl.pack(anchor="w", pady=(4, 0))
        
        # Divider - thinner
        tk.Frame(card_inner, bg=COLORS["border"], height=1).pack(fill="x", pady=12)
        
        # Credentials - compact
        tk.Label(card_inner, text="🔐 Enter Credentials", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        
        tk.Label(card_inner, text="Fixed Password:", bg=COLORS["card_bg"], 
                fg=COLORS["fg"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0,2))
        self.dec_pass = CyberEntry(card_inner, "Enter Your Password", True, width=300)
        self.dec_pass.pack(anchor="w", pady=(0, 8))
        
        tk.Label(card_inner, text="Recovery Key:", bg=COLORS["card_bg"], 
                fg=COLORS["fg"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0,2))
        self.dec_gen = CyberEntry(card_inner, "Enter Random Key", False, width=300)
        self.dec_gen.pack(anchor="w", pady=(0, 12))
        
        # ===== DECRYPT BUTTON - LARGE AND VISIBLE =====
        decrypt_frame = tk.Frame(card_inner, bg=COLORS["card_bg"])
        decrypt_frame.pack(fill="x", pady=(8, 12))
        
        CyberButton(decrypt_frame, "🔓 DECRYPT NOW", self.dec_run, 
                   bg=COLORS["danger"], width=300, height=50).pack(anchor="w")
        # ===== END DECRYPT BUTTON =====
        
        # Divider
        tk.Frame(card_inner, bg=COLORS["border"], height=1).pack(fill="x", pady=8)
        
        # Output - compact
        tk.Label(card_inner, text="📄 Output", bg=COLORS["card_bg"], 
                fg=COLORS["fg"], font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(4, 4))
        
        self.dec_out = scrolledtext.ScrolledText(card_inner, height=6,
                                                 bg=COLORS["input_bg"], fg=COLORS["fg"], 
                                                 bd=0, font=("Segoe UI", 9), wrap="word")
        self.dec_out.pack(fill="both", expand=True, anchor="w")

    def page_ana(self):
        self.clear_main()
        
        # Page header
        tk.Label(self.main_area, text="📈 Security Analytics", font=("Segoe UI", 24, "bold"), 
                bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor="w", pady=(0, 8))
        tk.Label(self.main_area, text="Analyze steganographic image security and detect anomalies", 
                font=("Segoe UI", 11), bg=COLORS["bg"], 
                fg=COLORS["fg_secondary"]).pack(anchor="w", pady=(0, 20))
        
        # Control panel
        head = tk.Frame(self.main_area, bg=COLORS["bg"])
        head.pack(fill="x", pady=(0,16))
        
        CyberButton(head, "Select Original", self.ana_sel_o, width=150, icon="🖼").pack(side="left", padx=(0, 8))
        CyberButton(head, "Select Stego", self.ana_sel_s, width=150, icon="🔐").pack(side="left", padx=(0, 20))
        CyberButton(head, "RUN ANALYSIS", self.ana_run, bg=COLORS["success"], 
                   width=180, icon="⚡").pack(side="left")
        
        # Results container
        row = tk.Frame(self.main_area, bg=COLORS["bg"])
        row.pack(fill="both", expand=True)
        
        # Analysis results (left)
        results_card = tk.Frame(row, bg=COLORS["card_bg"], width=350,
                               highlightbackground=COLORS["border"], highlightthickness=1)
        results_card.pack(side="left", fill="y", padx=(0,16))
        results_card.pack_propagate(False)
        
        results_header = tk.Frame(results_card, bg=COLORS["accent"], height=50)
        results_header.pack(fill="x")
        results_header.pack_propagate(False)
        tk.Label(results_header, text="📊 Analysis Results", font=("Segoe UI", 12, "bold"), 
                bg=COLORS["accent"], fg="white").pack(expand=True)
        
        self.ana_txt = scrolledtext.ScrolledText(results_card, width=40, 
                                                 bg=COLORS["card_bg"], fg=COLORS["fg"], 
                                                 bd=0, font=("Segoe UI", 10))
        self.ana_txt.pack(fill="both", expand=True, padx=12, pady=12)
        
        # Graph Area (right)
        graph_card = tk.Frame(row, bg=COLORS["card_bg"],
                             highlightbackground=COLORS["border"], highlightthickness=1)
        graph_card.pack(side="left", fill="both", expand=True)
        
        graph_header = tk.Frame(graph_card, bg=COLORS["info"], height=50)
        graph_header.pack(fill="x")
        graph_header.pack_propagate(False)
        tk.Label(graph_header, text="📈 RGB Histogram Analysis", font=("Segoe UI", 12, "bold"), 
                bg=COLORS["info"], fg="white").pack(expand=True)
        
        self.graph_area = tk.Frame(graph_card, bg=COLORS["card_bg"])
        self.graph_area.pack(fill="both", expand=True, padx=12, pady=12)

    # --- LOGIC HANDLERS ---
    def enc_browse(self):
        self.ep = filedialog.askopenfilename()
        if self.ep: self.enc_img_prev.config(text=os.path.basename(self.ep))
        
    def enc_run(self):
        if not hasattr(self, 'ep'): return
        pwd = self.enc_pass.get()
        
        # 1. Prepare Payload
        try:
            mode = self.enc_mode.get()
            if mode == "text":
                txt_data = self.enc_txt.get("1.0", "end").strip().encode('utf-8')
                if not txt_data: return messagebox.showwarning("Empty", "Enter text message")
                # Protocol: [TYPE: 0 (1 byte)] + [DATA]
                payload = b'\x00' + txt_data
                d_size = len(txt_data)
            else:
                if not hasattr(self, 'embed_file_path'): return messagebox.showwarning("Empty", "Select a file")
                with open(self.embed_file_path, 'rb') as f:
                    file_data = f.read()
                fname = os.path.basename(self.embed_file_path).encode('utf-8')
                # Protocol: [TYPE: 1 (1 byte)] + [NAME_LEN (4 bytes)] + [NAME] + [DATA]
                payload = b'\x01' + struct.pack('>I', len(fname)) + fname + file_data
                d_size = len(file_data)
                
        except Exception as e: return messagebox.showerror("Payload Error", str(e))
        
        save = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not save: return
        
        try:
            gen = secrets.token_hex(8)
            full_key = pwd + gen
            
            self.progress['value'] = 30
            # Encrypt Payload
            enc_data = encrypt_message(payload, full_key) # Helper handles bytes OK? Yes if Fernet used correctly.
            # NOTE: crypto_utils.encrypt_message expects str usually? Let's assume passed bytes ok, 
            # if not we need to update crypto_utils. 
            # *Self-Correction*: Standard Fernet encrypt() takes bytes. `encrypt_message` usually encodes str. 
            # I should verify `crypto_utils` or just use Fernet directly here to be safe.
            # Let's import Fernet locally to be robust.
            from cryptography.fernet import Fernet
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            # Key Derivation (Quick Inline to ensure binary compatibility)
            salt = b'secure_stego_salt' # In prod use per-file salt, but keeping compat with existing
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            f_key = base64.urlsafe_b64encode(kdf.derive(full_key.encode()))
            f_eng = Fernet(f_key)
            enc_data = f_eng.encrypt(payload) # Returns bytes
            
            if encode_lsb(self.ep, enc_data, save, full_key): # Pass raw encrypted bytes
                self.progress['value'] = 100
                self.enc_gen.set(gen)
                
                # BUG FIX: Add History - store FULL PATH
                self.auth.add_encryption_record(save, gen, d_size, len(enc_data))
                
                messagebox.showinfo("Success", "Data Hidden Successfully!")
                self.root.after(500, lambda: self.show_compare(self.ep, save))
            else:
                messagebox.showerror("Error", "Encoding Failed (Image too small?)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def dec_browse(self):
        self.dp = filedialog.askopenfilename()
        if self.dp: self.dec_lbl.config(text=os.path.basename(self.dp))
    
    def show_decrypted_message(self, message):
        """Display decrypted message in a dedicated popup window"""
        popup = tk.Toplevel(self.root)
        popup.title("Decrypted Message")
        popup.geometry("600x400")
        popup.configure(bg=COLORS["bg"])
        
        # Center the popup
        popup.update_idletasks()
        x = (popup.winfo_screenwidth() // 2) - 300
        y = (popup.winfo_screenheight() // 2) - 200
        popup.geometry(f"600x400+{x}+{y}")
        
        # Header
        header = tk.Frame(popup, bg=COLORS["success"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="✓ Decryption Successful", font=("Segoe UI", 16, "bold"), 
                bg=COLORS["success"], fg="white").pack(expand=True)
        
        # Message display
        msg_frame = tk.Frame(popup, bg=COLORS["card_bg"], padx=20, pady=20)
        msg_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        tk.Label(msg_frame, text="Decrypted Content:", bg=COLORS["card_bg"], 
                fg=COLORS["accent"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))
        
        text_widget = scrolledtext.ScrolledText(msg_frame, bg=COLORS["input_bg"], 
                                                fg="white", font=("Segoe UI", 11),
                                                wrap="word", bd=0)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", message)
        text_widget.config(state="disabled")  # Make read-only
        
        # Close button
        CyberButton(popup, "CLOSE", popup.destroy, width=150).pack(pady=10)
        
    def dec_run(self):
        if not hasattr(self, 'dp'): return
        try:
            full_key = self.dec_pass.get() + self.dec_gen.get()
            res_bytes = decode_lsb(self.dp, full_key)
            if not res_bytes: 
                messagebox.showwarning("Failed", "No data found or wrong key.")
                return
            
            # Decrypt handling
            # Inline decrypt to match the encrypt logic
            from cryptography.fernet import Fernet
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            salt = b'secure_stego_salt'
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            f_key = base64.urlsafe_b64encode(kdf.derive(full_key.encode()))
            f_eng = Fernet(f_key)
            
            try:
                decrypted_payload = f_eng.decrypt(res_bytes) # Raw payload
            except:
                # Fallback for old text-only messages (Before update)
                # If decrypt fails, maybe it was encrypted with old `encrypt_message`?
                # or maybe just wrong key.
                plain = decrypt_message(res_bytes, full_key) # Try old method
                decrypted_payload = b'\x00' + plain.encode() # Treat as text
                
            # Parse Protocol
            type_byte = decrypted_payload[0]
            
            if type_byte == 0: # Text
                msg = decrypted_payload[1:].decode('utf-8', errors='replace')
                self.dec_out.delete("1.0", "end")
                self.dec_out.insert("1.0", msg)
                
                # Show visual popup with message
                self.show_decrypted_message(msg)
                
            elif type_byte == 1: # File
                # [1][4:Len][Name][Data]
                offset = 1
                name_len = struct.unpack('>I', decrypted_payload[offset:offset+4])[0]
                offset += 4
                filename = decrypted_payload[offset:offset+name_len].decode('utf-8')
                offset += name_len
                file_data = decrypted_payload[offset:]
                
                # Prompt Save
                save_path = filedialog.asksaveasfilename(initialfile=filename, title=f"Save Extracted {filename}")
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    messagebox.showinfo("File Extracted", f"Successfully saved:\n{filename}")
                else:
                    messagebox.showwarning("Cancelled", "File extraction cancelled (not saved).")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption Error: {e}")

    def ana_sel_o(self): self.ap1 = filedialog.askopenfilename()
    def ana_sel_s(self): self.ap2 = filedialog.askopenfilename()
    
    def ana_run(self):
        if not hasattr(self, 'ap1') or not hasattr(self, 'ap2'): return
        
        # Text Analysis
        res = self.security.analyze_stego_image(self.ap1, self.ap2)
        txt = f"SCORE: {res.get('final_score')}/100\n\n"
        for r in res.get('score_reasons', []): txt += f"⚠ {r}\n"
        self.ana_txt.delete("1.0", "end"); self.ana_txt.insert("1.0", txt)
        
        # Graphs
        for w in self.graph_area.winfo_children(): 
            if isinstance(w, tk.Canvas): w.destroy() # clear old canvas
            elif w.winfo_class() == "Frame": w.destroy() # clear matplotlib toolbar
            elif w['text'] != "RGB Histogram Analysis": w.destroy()

        fig = plt.Figure(figsize=(5, 4), dpi=100, facecolor=COLORS["card_bg"])
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLORS["card_bg"])
        
        # Plot Histograms
        img = Image.open(self.ap2).convert('RGB')
        arr = np.array(img)
        colors = ['red', 'green', 'blue']
        for i, c in enumerate(colors):
            hist, _ = np.histogram(arr[:,:,i], bins=256, range=(0, 256))
            ax.plot(hist, color=c, alpha=0.7)
            
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white') 
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        
        canvas = FigureCanvasTkAgg(fig, master=self.graph_area)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        
        self.show_compare(self.ap1, self.ap2)

    def show_compare(self, p1, p2):
        top = tk.Toplevel(self.root)
        top.title("Visual Proof")
        top.configure(bg=COLORS["bg"])
        
        f = tk.Frame(top, bg=COLORS["bg"]); f.pack(padx=20, pady=20)
        
        def show(path, txt):
            fr = tk.Frame(f, bg="white", bd=1); fr.pack(side="left", padx=10)
            tk.Label(fr, text=txt, bg="white", font=("bold", 12)).pack()
            try:
                i = Image.open(path); i.thumbnail((300, 300))
                ph = ImageTk.PhotoImage(i)
                l = tk.Label(fr, image=ph, bg="white"); l.image = ph; l.pack()
            except: pass
            
        show(p1, "Original")
        tk.Label(f, text="≈", font=("bold", 40), bg=COLORS["bg"], fg=COLORS["success"]).pack(side="left")
        show(p2, "Stego")



    def page_forensic(self):
        self.clear_main()

        tk.Label(self.main_area, text="🕵️ Digital Forensics", 
             font=("Segoe UI", 24, "bold"), 
             bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor="w", pady=(0,10))

        # Select Image
        CyberButton(self.main_area, "Select Suspicious Image", 
                self.select_forensic_image, width=250).pack(pady=10)

        self.forensic_label = tk.Label(self.main_area, text="No file selected",
                                  bg=COLORS["bg"], fg=COLORS["fg_secondary"])
        self.forensic_label.pack()

        # Run Analysis
        CyberButton(self.main_area, "Run Forensic Analysis", 
                self.run_forensic_analysis, bg=COLORS["danger"], width=250).pack(pady=15)

    # Result Box
        self.result_box = scrolledtext.ScrolledText(self.main_area, height=15,
                                               bg=COLORS["input_bg"], fg=COLORS["fg"])
        self.result_box.pack(fill="both", expand=True, pady=10)


    def select_forensic_image(self):
        self.forensic_image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png *.jpg *.bmp")]
        )
        self.forensic_label.config(text=self.forensic_image_path)

    def run_forensic_analysis(self):
        if not hasattr(self, "forensic_image_path"):
            messagebox.showerror("Error", "Please select an image first")
            return

        try:
            case_id, case_path = create_case("gui_case")
            evidence_path = add_evidence(case_path, self.forensic_image_path)

            file_hash = compute_hash(evidence_path)
            is_stego, ratio = detect_stego(evidence_path)
            analysis = analyze_image(evidence_path)
            extraction = forensic_extract(evidence_path)

            result_text = f"""
=== FORENSIC RESULTS ===

Hash: {file_hash}
Stego Detected: {is_stego}
LSB Ratio: {ratio:.4f}
Entropy: {analysis['entropy']:.4f}

Extracted Data:
{extraction.get('data', 'None')}
"""

            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, result_text)

            findings = {
                "Hash": file_hash,
                "Stego Detected": is_stego,
                "LSB Ratio": ratio,
                "Entropy": analysis["entropy"],
                "Extracted Data": extraction.get("data", "None")
            }

            report_path = generate_report(case_id, findings)

            messagebox.showinfo("Success", f"Report saved at:\n{report_path}")

        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    StegoApp()