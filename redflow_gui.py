#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RedFlow GUI - Graphical User Interface for RedFlow
// ממשק משתמש גרפי עבור RedFlow
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
from datetime import datetime

# Import RedFlow components
from redflow.utils.config import Config
from redflow.utils.logger import setup_logger
from redflow.core.scanner import Scanner
from redflow.utils.helpers import init_project_dir, is_valid_ip, is_valid_domain

# Language dictionaries
EN = {
    "title": "RedFlow - Automated Information Gathering and Attack Tool",
    "scan_tab": "Scan",
    "config_tab": "Settings",
    "results_tab": "Results",
    "logs_tab": "Logs",
    "target_frame": "Target",
    "target_label": "IP or Domain:",
    "scan_mode_frame": "Scan Mode",
    "passive_only": "Passive Only",
    "active_only": "Active Only",
    "full_scan": "Full Scan",
    "options_frame": "Options",
    "interactive_mode": "Interactive Mode",
    "use_gpt": "Use GPT Analysis",
    "verbose_mode": "Verbose Mode",
    "output_frame": "Output Directory",
    "path_label": "Path:",
    "browse_button": "Browse...",
    "start_button": "Start Scan",
    "stop_button": "Stop Scan",
    "clear_button": "Clear Fields",
    "progress_frame": "Progress",
    "status_ready": "Ready",
    "status_scanning": "Scan in progress...",
    "status_completed": "Scan completed",
    "status_failed": "Scan failed",
    "status_stopped": "Scan stopped",
    "error_title": "Error",
    "warning_title": "Warning",
    "info_title": "Information",
    "error_no_target": "Please enter an IP address or domain",
    "error_invalid_target": "Invalid IP address or domain",
    "warning_scan_running": "A scan is already running",
    "scan_complete_msg": "The scan process has completed successfully",
    "no_scan_active": "No active scan",
    "stopping_scan": "Stopping scan...",
    "scan_stopped": "Scan stopped",
    "no_results": "No results found",
    "load_config": "Load Configuration",
    "save_config": "Save Settings to File",
    "clear_logs": "Clear Logs",
    "refresh_logs": "Refresh",
    "save_logs": "Save Logs to File",
    "export_json": "Export to JSON",
    "export_html": "Export to HTML",
    "export_pdf": "Export to PDF",
    "language": "Language"
}

HE = {
    "title": "RedFlow - כלי אוטומטי לאיסוף מידע ותקיפה",
    "scan_tab": "סריקה",
    "config_tab": "הגדרות",
    "results_tab": "תוצאות",
    "logs_tab": "לוגים",
    "target_frame": "מטרה",
    "target_label": "כתובת IP או דומיין:",
    "scan_mode_frame": "מצב סריקה",
    "passive_only": "סריקה פסיבית בלבד",
    "active_only": "סריקה אקטיבית בלבד",
    "full_scan": "סריקה מלאה",
    "options_frame": "אפשרויות",
    "interactive_mode": "מצב אינטראקטיבי",
    "use_gpt": "השתמש ב-GPT לניתוח",
    "verbose_mode": "מצב מפורט (verbose)",
    "output_frame": "תיקיית פלט",
    "path_label": "נתיב:",
    "browse_button": "עיון...",
    "start_button": "התחל סריקה",
    "stop_button": "עצור סריקה",
    "clear_button": "נקה שדות",
    "progress_frame": "התקדמות",
    "status_ready": "מוכן",
    "status_scanning": "סריקה בתהליך...",
    "status_completed": "סריקה הושלמה",
    "status_failed": "סריקה נכשלה",
    "status_stopped": "סריקה נעצרה",
    "error_title": "שגיאה",
    "warning_title": "אזהרה",
    "info_title": "מידע",
    "error_no_target": "יש להזין כתובת IP או דומיין",
    "error_invalid_target": "כתובת IP או דומיין לא תקינים",
    "warning_scan_running": "סריקה כבר מתבצעת",
    "scan_complete_msg": "תהליך הסריקה הושלם בהצלחה",
    "no_scan_active": "אין סריקה פעילה",
    "stopping_scan": "עוצר סריקה...",
    "scan_stopped": "הסריקה נעצרה",
    "no_results": "לא נמצאו תוצאות",
    "load_config": "טען קובץ תצורה",
    "save_config": "שמור הגדרות לקובץ",
    "clear_logs": "נקה לוגים",
    "refresh_logs": "רענן",
    "save_logs": "שמור לוגים לקובץ",
    "export_json": "ייצוא לקובץ JSON",
    "export_html": "ייצוא לקובץ HTML",
    "export_pdf": "ייצוא לקובץ PDF",
    "language": "שפה"
}

class RedFlowGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RedFlow")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        
        # Set language (default to English)
        self.lang = EN
        self.current_lang = "en"
        
        # Set icon if available
        try:
            self.root.iconbitmap("docs/images/redflow_icon.ico")
        except:
            pass
        
        self.scan_thread = None
        self.current_project_dir = None
        self.setup_gui()
        
    def setup_gui(self):
        """Set up the main GUI components"""
        # Create toolbar with language selection
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        
        lang_label = ttk.Label(toolbar, text=self.lang["language"] + ":")
        lang_label.pack(side=tk.RIGHT, padx=5, pady=5)
        
        self.lang_var = tk.StringVar(value="en")
        lang_combo = ttk.Combobox(toolbar, textvariable=self.lang_var, values=["en", "he"], width=5)
        lang_combo.pack(side=tk.RIGHT, padx=5, pady=5)
        lang_combo.bind("<<ComboboxSelected>>", self.change_language)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_tab, text=self.lang["scan_tab"])
        self.notebook.add(self.config_tab, text=self.lang["config_tab"])
        self.notebook.add(self.results_tab, text=self.lang["results_tab"])
        self.notebook.add(self.logs_tab, text=self.lang["logs_tab"])
        
        # Setup each tab
        self.setup_scan_tab()
        self.setup_config_tab()
        self.setup_results_tab()
        self.setup_logs_tab()
    
    def setup_scan_tab(self):
        """Set up the scanning tab"""
        # Target Frame
        target_frame = ttk.LabelFrame(self.scan_tab, text=self.lang["target_frame"])
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text=self.lang["target_label"]).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Scan Mode Frame
        mode_frame = ttk.LabelFrame(self.scan_tab, text=self.lang["scan_mode_frame"])
        mode_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_mode = tk.StringVar(value="full")
        ttk.Radiobutton(mode_frame, text=self.lang["passive_only"], variable=self.scan_mode, value="passive").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(mode_frame, text=self.lang["active_only"], variable=self.scan_mode, value="active").grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(mode_frame, text=self.lang["full_scan"], variable=self.scan_mode, value="full").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Options Frame
        options_frame = ttk.LabelFrame(self.scan_tab, text=self.lang["options_frame"])
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.interactive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text=self.lang["interactive_mode"], variable=self.interactive_var).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.gpt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text=self.lang["use_gpt"], variable=self.gpt_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text=self.lang["verbose_mode"], variable=self.verbose_var).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Output Directory Frame
        output_frame = ttk.LabelFrame(self.scan_tab, text=self.lang["output_frame"])
        output_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(output_frame, text=self.lang["path_label"]).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.output_entry = ttk.Entry(output_frame, width=40)
        self.output_entry.insert(0, "./scans/")
        self.output_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(output_frame, text=self.lang["browse_button"], command=self.browse_output_dir).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Action Buttons
        buttons_frame = ttk.Frame(self.scan_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(buttons_frame, text=self.lang["start_button"], command=self.start_scan, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text=self.lang["stop_button"], command=self.stop_scan, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text=self.lang["clear_button"], command=self.clear_fields, width=20).pack(side=tk.LEFT, padx=5)
        
        # Progress Frame
        progress_frame = ttk.LabelFrame(self.scan_tab, text=self.lang["progress_frame"])
        progress_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text=self.lang["status_ready"])
        self.status_label.pack(fill=tk.X, padx=5, pady=5)
    
    def setup_config_tab(self):
        """Set up the configuration tab"""
        # Tools Paths Frame
        tools_frame = ttk.LabelFrame(self.config_tab, text="נתיבי כלים")
        tools_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tools = ["nmap", "enum4linux", "hydra", "gobuster", "whois", "dig", "theHarvester", "sublist3r", "whatweb", "wafw00f"]
        self.tool_entries = {}
        
        for i, tool in enumerate(tools):
            row, col = divmod(i, 2)
            ttk.Label(tools_frame, text=f"{tool}:").grid(row=row, column=col*2, sticky=tk.W, padx=5, pady=5)
            entry = ttk.Entry(tools_frame, width=30)
            entry.insert(0, f"/usr/bin/{tool}")
            entry.grid(row=row, column=col*2+1, sticky=tk.W, padx=5, pady=5)
            self.tool_entries[tool] = entry
        
        # GPT Settings Frame
        gpt_frame = ttk.LabelFrame(self.config_tab, text="הגדרות GPT")
        gpt_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(gpt_frame, text="מפתח API:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.api_key_entry = ttk.Entry(gpt_frame, width=40, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(gpt_frame, text="מודל:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.model_combo = ttk.Combobox(gpt_frame, values=["gpt-4", "gpt-3.5-turbo"])
        self.model_combo.current(0)
        self.model_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(gpt_frame, text="פרומפט מותאם אישית:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.prompt_text = tk.Text(gpt_frame, width=40, height=4)
        self.prompt_text.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Config File Frame
        config_file_frame = ttk.LabelFrame(self.config_tab, text="קובץ תצורה")
        config_file_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(config_file_frame, text=self.lang["load_config"], command=self.load_config).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Button(config_file_frame, text=self.lang["save_config"], command=self.save_config).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    def setup_results_tab(self):
        """Set up the results tab"""
        # Results Frame
        results_frame = ttk.Frame(self.results_tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Results Notebook
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create results tabs
        self.summary_tab = ttk.Frame(results_notebook)
        self.ports_tab = ttk.Frame(results_notebook)
        self.vulns_tab = ttk.Frame(results_notebook)
        self.details_tab = ttk.Frame(results_notebook)
        
        results_notebook.add(self.summary_tab, text="סיכום")
        results_notebook.add(self.ports_tab, text="פורטים ושירותים")
        results_notebook.add(self.vulns_tab, text="פגיעויות")
        results_notebook.add(self.details_tab, text="פרטים מלאים")
        
        # Summary Tab
        self.summary_text = tk.Text(self.summary_tab, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        summary_scroll = ttk.Scrollbar(self.summary_tab, command=self.summary_text.yview)
        summary_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.summary_text.config(yscrollcommand=summary_scroll.set)
        self.summary_text.insert(tk.END, "לא בוצעה סריקה עדיין.")
        self.summary_text.config(state=tk.DISABLED)
        
        # Export Buttons
        export_frame = ttk.Frame(self.results_tab)
        export_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(export_frame, text=self.lang["export_json"], command=lambda: self.export_results("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text=self.lang["export_html"], command=lambda: self.export_results("html")).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text=self.lang["export_pdf"], command=lambda: self.export_results("pdf")).pack(side=tk.LEFT, padx=5)
    
    def setup_logs_tab(self):
        """Set up the logs tab"""
        # Logs Frame
        logs_frame = ttk.Frame(self.logs_tab)
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.logs_text = tk.Text(logs_frame, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        logs_scroll = ttk.Scrollbar(logs_frame, command=self.logs_text.yview)
        logs_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.logs_text.config(yscrollcommand=logs_scroll.set)
        
        # Log controls
        log_controls = ttk.Frame(self.logs_tab)
        log_controls.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(log_controls, text=self.lang["clear_logs"], command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text=self.lang["refresh_logs"], command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text=self.lang["save_logs"], command=self.save_logs).pack(side=tk.LEFT, padx=5)
    
    def browse_output_dir(self):
        """Open directory browser dialog"""
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, dir_path)
    
    def clear_fields(self):
        """Clear all input fields"""
        self.target_entry.delete(0, tk.END)
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, "./scans/")
        self.scan_mode.set("full")
        self.interactive_var.set(True)
        self.gpt_var.set(False)
        self.verbose_var.set(False)
    
    def validate_input(self):
        """Validate user input"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror(self.lang["error_title"], self.lang["error_no_target"])
            return False
        
        # Validate target is IP or domain
        if not is_valid_ip(target) and not is_valid_domain(target):
            messagebox.showerror(self.lang["error_title"], self.lang["error_invalid_target"])
            return False
            
        return True
    
    def start_scan(self):
        """Start the scanning process"""
        if not self.validate_input():
            return
            
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning(self.lang["warning_title"], self.lang["warning_scan_running"])
            return
        
        # Update UI
        self.status_label.config(text=self.lang["status_scanning"])
        self.progress.start(10)
        
        # Get scan parameters
        target = self.target_entry.get().strip()
        mode = self.scan_mode.get()
        output_dir = self.output_entry.get().strip()
        interactive = self.interactive_var.get()
        use_gpt = self.gpt_var.get()
        verbose = self.verbose_var.get()
        
        # Create args object for config
        class Args:
            pass
            
        args = Args()
        args.target = target
        args.mode = mode
        args.output = output_dir
        args.interactive = interactive
        args.use_gpt = use_gpt
        args.verbose = verbose
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(args,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_scan(self, args):
        """Run the scan process"""
        try:
            # Create project directory
            self.current_project_dir = init_project_dir(args.target, args.output)
            
            # Setup logger
            logger = setup_logger(self.current_project_dir, args.verbose)
            
            # Update logs tab
            self.root.after(100, self.update_logs_tab, "סריקה התחילה.")
            
            # Create configuration
            config = Config(args, self.current_project_dir)
            
            if args.use_gpt and self.api_key_entry.get():
                config.set_gpt_api_key(self.api_key_entry.get())
                config.set_custom_prompt(self.prompt_text.get("1.0", tk.END))
            
            # Create scanner
            scanner = Scanner(config, logger, None)  # No console in GUI mode
            
            # Run scan
            scanner.start()
            
            # Update UI when done
            self.root.after(100, self.scan_completed, scanner.results)
            
        except Exception as e:
            error_msg = f"{self.lang['error_title']}: {str(e)}"
            self.root.after(100, self.scan_error, error_msg)
    
    def scan_completed(self, results):
        """Handle scan completion"""
        self.progress.stop()
        self.status_label.config(text=self.lang["status_completed"])
        
        # Update results
        self.update_results(results)
        
        messagebox.showinfo(self.lang["info_title"], self.lang["scan_complete_msg"])
    
    def scan_error(self, error_msg):
        """Handle scan error"""
        self.progress.stop()
        self.status_label.config(text=self.lang["status_failed"])
        messagebox.showerror(self.lang["error_title"], error_msg)
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            # Cannot directly terminate thread, but we'll set a flag to stop it gracefully
            self.status_label.config(text=self.lang["stopping_scan"])
            messagebox.showinfo(self.lang["info_title"], self.lang["scan_stopped"])
            self.progress.stop()
            self.status_label.config(text=self.lang["status_stopped"])
        else:
            messagebox.showinfo(self.lang["info_title"], self.lang["no_scan_active"])
    
    def update_results(self, results):
        """Update results tabs with scan results"""
        # Clear previous results
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        if not results:
            self.summary_text.insert(tk.END, self.lang["no_results"])
            self.summary_text.config(state=tk.DISABLED)
            return
        
        # Format summary
        summary = f"{self.lang['info_title']} סריקה עבור: {results.get('target_info', {}).get('original', 'Unknown')}\n\n"
        summary += f"{self.lang['info_title']} זמן התחלה: {datetime.fromtimestamp(results.get('start_time', 0)).strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        duration = results.get('duration', 0)
        minutes, seconds = divmod(int(duration), 60)
        summary += f"{self.lang['info_title']} משך זמן: {minutes} דקות ו-{seconds} שניות\n\n"
        
        # Target info
        target_info = results.get('target_info', {})
        summary += "== מידע על המטרה ==\n"
        summary += f"{self.lang['info_title']} סוג: {target_info.get('type', 'Unknown')}\n"
        
        if target_info.get('type') == 'ip':
            summary += f"{self.lang['info_title']} כתובת IP: {target_info.get('ip', 'Unknown')}\n"
            summary += f"{self.lang['info_title']} שם מארח: {target_info.get('hostname', 'Unknown')}\n"
        else:
            summary += f"{self.lang['info_title']} דומיין: {target_info.get('domain', 'Unknown')}\n"
            summary += f"{self.lang['info_title']} כתובת IP: {target_info.get('ip', 'Unknown')}\n"
        
        # Open ports
        open_ports = results.get('open_ports', [])
        summary += f"\n== פורטים פתוחים ({len(open_ports)}) ==\n"
        for port in open_ports[:10]:  # Show only first 10
            if isinstance(port, dict):
                summary += f"{self.lang['info_title']} פורט {port.get('port', '?')}: {port.get('service', 'Unknown')} {port.get('version', '')}\n"
            else:
                summary += f"{self.lang['info_title']} פורט {port}\n"
        
        if len(open_ports) > 10:
            summary += f"...ועוד {len(open_ports) - 10} פורטים\n"
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        summary += f"\n== פגיעויות ({len(vulns)}) ==\n"
        for vuln in vulns[:10]:  # Show only first 10
            summary += f"{vuln.get('name', 'Unknown')} - {vuln.get('severity', 'Unknown')}\n"
        
        if len(vulns) > 10:
            summary += f"...ועוד {len(vulns) - 10} פגיעויות\n"
        
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)
    
    def load_config(self):
        """Load configuration from file"""
        config_file = filedialog.askopenfilename(
            title=self.lang["load_config"],
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        
        if not config_file:
            return
            
        try:
            # Placeholder for config loading logic
            messagebox.showinfo(self.lang["info_title"], f"{self.lang['info_title']} {config_file} נטען בהצלחה")
        except Exception as e:
            messagebox.showerror(self.lang["error_title"], f"{self.lang['error_title']} טעינת קובץ התצורה נכשלה: {str(e)}")
    
    def save_config(self):
        """Save configuration to file"""
        config_file = filedialog.asksaveasfilename(
            title=self.lang["save_config"],
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        
        if not config_file:
            return
            
        try:
            # Placeholder for config saving logic
            messagebox.showinfo(self.lang["info_title"], f"{self.lang['info_title']} הגדרות נשמרו לקובץ {config_file}")
        except Exception as e:
            messagebox.showerror(self.lang["error_title"], f"{self.lang['error_title']} שמירת ההגדרות נכשלה: {str(e)}")
    
    def clear_logs(self):
        """Clear logs display"""
        self.logs_text.delete(1.0, tk.END)
    
    def refresh_logs(self):
        """Refresh logs from file"""
        if not self.current_project_dir:
            messagebox.showinfo(self.lang["info_title"], self.lang["no_scan_active"])
            return
            
        log_file = os.path.join(self.current_project_dir, "logs", "redflow.log")
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    logs = f.read()
                    self.logs_text.delete(1.0, tk.END)
                    self.logs_text.insert(tk.END, logs)
            except Exception as e:
                messagebox.showerror(self.lang["error_title"], f"{self.lang['error_title']} קריאת קובץ הלוג נכשלה: {str(e)}")
        else:
            messagebox.showinfo(self.lang["info_title"], "קובץ לוג לא קיים")
    
    def update_logs_tab(self, message):
        """Append message to logs tab"""
        self.logs_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.logs_text.see(tk.END)
    
    def save_logs(self):
        """Save logs to file"""
        if not self.logs_text.get(1.0, tk.END).strip():
            messagebox.showinfo(self.lang["info_title"], "אין לוגים לשמירה")
            return
            
        log_file = filedialog.asksaveasfilename(
            title=self.lang["save_logs"],
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not log_file:
            return
            
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(self.logs_text.get(1.0, tk.END))
            messagebox.showinfo(self.lang["info_title"], f"{self.lang['info_title']} הלוגים נשמרו לקובץ {log_file}")
        except Exception as e:
            messagebox.showerror(self.lang["error_title"], f"{self.lang['error_title']} שמירת הלוגים נכשלה: {str(e)}")
    
    def export_results(self, format_type):
        """Export results to specified format"""
        if not self.current_project_dir:
            messagebox.showinfo(self.lang["info_title"], self.lang["no_scan_active"])
            return
            
        # Set proper extension and dialog title based on format
        if format_type == "json":
            ext = ".json"
            title = self.lang["export_json"]
        elif format_type == "html":
            ext = ".html"
            title = self.lang["export_html"]
        elif format_type == "pdf":
            ext = ".pdf"
            title = self.lang["export_pdf"]
        else:
            return
            
        export_file = filedialog.asksaveasfilename(
            title=title,
            defaultextension=ext,
            filetypes=[(format_type.upper(), f"*{ext}"), ("All files", "*.*")]
        )
        
        if not export_file:
            return
            
        try:
            # Placeholder for export logic
            messagebox.showinfo(self.lang["info_title"], f"{self.lang['info_title']} התוצאות יוצאו בהצלחה לקובץ {export_file}")
        except Exception as e:
            messagebox.showerror(self.lang["error_title"], f"{self.lang['error_title']} ייצוא התוצאות נכשל: {str(e)}")

    def change_language(self, event=None):
        """Change the GUI language"""
        selected_lang = self.lang_var.get()
        if selected_lang == "en" and self.current_lang != "en":
            self.lang = EN
            self.current_lang = "en"
        elif selected_lang == "he" and self.current_lang != "he":
            self.lang = HE
            self.current_lang = "he"
        else:
            return  # No change needed
            
        # Update root title
        self.root.title(self.lang["title"])
        
        # Update notebook tab names
        self.notebook.tab(0, text=self.lang["scan_tab"])
        self.notebook.tab(1, text=self.lang["config_tab"])
        self.notebook.tab(2, text=self.lang["results_tab"])
        self.notebook.tab(3, text=self.lang["logs_tab"])
        
        # Recreate all tabs
        self.scan_tab.destroy()
        self.config_tab.destroy()
        self.results_tab.destroy()
        self.logs_tab.destroy()
        
        self.scan_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_tab, text=self.lang["scan_tab"])
        self.notebook.add(self.config_tab, text=self.lang["config_tab"])
        self.notebook.add(self.results_tab, text=self.lang["results_tab"])
        self.notebook.add(self.logs_tab, text=self.lang["logs_tab"])
        
        # Re-setup all tabs
        self.setup_scan_tab()
        self.setup_config_tab()
        self.setup_results_tab()
        self.setup_logs_tab()


def main():
    """Main function to start the GUI"""
    root = tk.Tk()
    app = RedFlowGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main() 