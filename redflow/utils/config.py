"""
Configuration module for managing RedFlow settings
// הערה: מודול תצורה לניהול הגדרות RedFlow
"""

import os
import json
import yaml
from pathlib import Path


class Config:
    """Class for managing program settings // מחלקה לניהול הגדרות התוכנית"""
    
    def __init__(self, args, project_dir):
        """
        Initialize configuration object
        // אתחול אובייקט התצורה
        
        Args:
            args: Command line arguments
            project_dir: Project directory path
        """
        self.target = args.target
        self.mode = args.mode
        self.output_dir = project_dir
        self.interactive = args.interactive
        self.use_gpt = args.use_gpt
        self.verbose = args.verbose
        self.scan_vulns = getattr(args, 'scan_vulns', True)  # Default to True if not provided
        self.gpt_model = getattr(args, 'gpt_model', 'gpt-4o-mini')  # Get GPT model from args or default to gpt-4o-mini
        
        # Project directory paths // נתיבים לתיקיות הפרויקט
        self.scans_dir = os.path.join(self.output_dir, "scans")
        self.logs_dir = os.path.join(self.output_dir, "logs")
        self.summaries_dir = os.path.join(self.output_dir, "summaries")
        self.scripts_dir = os.path.join(self.output_dir, "scripts")
        
        # Create directories if they don't exist // יצירת תיקיות אם לא קיימות
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.summaries_dir, exist_ok=True)
        os.makedirs(self.scripts_dir, exist_ok=True)
        
        # Load default settings
        self.load_default_settings()
        
        # Load settings from external config file if it exists
        self.load_config_file()
        
        # Save scan metadata
        self.save_metadata()
    
    def load_default_settings(self):
        """Load default settings and configuration files // טעינת הגדרות ברירת מחדל"""
        # Tool paths for Kali Linux environment
        # In Windows environment, these are only for demonstration
        self.tool_paths = {
            "nmap": "/usr/bin/nmap",
            "enum4linux": "/usr/bin/enum4linux",
            "hydra": "/usr/bin/hydra",
            "gobuster": "/usr/bin/gobuster",
            "whois": "/usr/bin/whois",
            "dig": "/usr/bin/dig",
            "theHarvester": "/usr/bin/theHarvester",
            "sublist3r": "/usr/bin/sublist3r",
            "whatweb": "/usr/bin/whatweb",
            "wafw00f": "/usr/bin/wafw00f"
        }
        
        # Paths to custom scripts // נתיבים לסקריפטים מותאמים אישית
        self.script_paths = {
            "custom_scan": os.path.join(self.scripts_dir, "custom_scan.py"),
            "vuln_check": os.path.join(self.scripts_dir, "vuln_check.py"),
            "exploit": os.path.join(self.scripts_dir, "exploit.py")
        }
        
        self.wordlist_paths = {
            "dirb_common": "/usr/share/wordlists/dirb/common.txt",
            "rockyou": "/usr/share/wordlists/rockyou.txt",
            "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "usernames": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        }
        
        # Default exploitation settings
        self.exploitation = {
            "metasploit_auto_detect": True,
            "auto_update_searchsploit": True,
            "exploitdb_path": "/usr/share/exploitdb",
            "max_exploits_to_suggest": 10
        }
        
        # Settings for different tools // הגדרות עבור כלים שונים
        self.tool_settings = {
            "nmap": {
                "default_args": "-sV -A",
                "common_scripts": ["vuln", "ftp-anon", "smb-os-discovery", "http-enum"]
            },
            "gobuster": {
                "default_args": "dir",
                "default_wordlist": self.wordlist_paths["dirb_common"],
                "threads": 10
            },
            "hydra": {
                "default_userlist": self.wordlist_paths["usernames"],
                "default_passlist": self.wordlist_paths["rockyou"],
                "default_protocols": ["ssh", "ftp", "http-post-form"]
            }
        }
        
        self.port_service_map = {
            "21": "ftp",
            "22": "ssh",
            "23": "telnet",
            "25": "smtp",
            "53": "dns",
            "80": "http",
            "110": "pop3",
            "111": "rpcbind",
            "135": "msrpc",
            "139": "netbios-ssn",
            "143": "imap",
            "443": "https",
            "445": "microsoft-ds",
            "993": "imaps",
            "995": "pop3s",
            "1723": "pptp",
            "3306": "mysql",
            "3389": "ms-wbt-server",
            "5900": "vnc",
            "8080": "http-proxy"
        }
        
        # GPT-related settings // הגדרות הקשורות ל-GPT
        self.gpt_settings = {
            "api_key": os.environ.get("OPENAI_API_KEY", ""),  # Default from environment
            "model": self.gpt_model,  # Use the model specified in args or default
            "temperature": 0.3,  # Lower temperature for more focused results
            "max_tokens": 500,  # Enough for detailed exploit guidance
            "top_p": 1.0,  # Default value for standard probability distribution
            "frequency_penalty": 0.0,  # No penalty for term repetition (good for commands)
            "presence_penalty": 0.0,  # No penalty for introducing new topics
            "custom_prompt": "",  # Custom user prompt
            "system_prompt": """You are an advanced Offensive Security expert and red team operator.

You think like an attacker. You know how to identify weak spots in networks, services, and configurations. You take every piece of data — a port, a banner, a misconfigured service — and turn it into an opportunity for deeper compromise.

You are assisting a professional penetration tester running a custom automation tool. The tool feeds you output from recon phases such as Nmap scans, service banners, directory listings, SMB enumeration, login brute-force attempts, etc.

Your mission:
1. Read the output and extract key insights.
2. Recommend the next most effective and high-impact step (e.g., exploit, enumeration tool, post-exploitation script).
3. Match services to known vulnerabilities or CVEs.
4. Suggest Metasploit modules or manual attack techniques.
5. Explain what misconfigurations or entry points you see — and how you'd exploit them.
6. If you detect dead ends or errors, explain what went wrong and how to bypass or pivot.

Be ruthless, efficient, and clear. Always think in terms of exploitation paths, privilege escalation, lateral movement, persistence, and data exfiltration.

Output your response like you're advising an elite red teamer in the middle of a live engagement."""
        }
    
    def load_config_file(self):
        """Load settings from external configuration file // טעינת הגדרות מקובץ תצורה חיצוני"""
        config_file = os.path.join(os.path.dirname(self.output_dir), "config.yaml")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                    if config_data:
                        # Update GPT settings
                        if 'gpt' in config_data:
                            self.gpt_settings.update(config_data['gpt'])
                        
                        # Update script paths
                        if 'scripts' in config_data:
                            self.script_paths.update(config_data['scripts'])
                        
                        # Update tool paths
                        if 'tools' in config_data:
                            self.tool_paths.update(config_data['tools'])
                            
                        # Update exploitation settings
                        if 'exploitation' in config_data:
                            self.exploitation = config_data['exploitation']
                        else:
                            # Default exploitation settings
                            self.exploitation = {
                                "metasploit_auto_detect": True,
                                "auto_update_searchsploit": True,
                                "exploitdb_path": "/usr/share/exploitdb",
                                "max_exploits_to_suggest": 10
                            }
            except Exception as e:
                print(f"Error loading configuration file: {str(e)}")
    
    def save_metadata(self):
        """Save metadata about the current scan // שמירת מטא-דאטה על הסריקה הנוכחית"""
        metadata = {
            "target": self.target,
            "mode": self.mode,
            "interactive": self.interactive,
            "started_at": self._get_timestamp(),
            "version": "0.1.0"
        }
        
        with open(os.path.join(self.output_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=4)
    
    def _get_timestamp(self):
        """Returns current timestamp // מחזיר חותמת זמן נוכחית"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_output_file(self, tool_name, extension="txt"):
        """
        Returns path to output file for a tool
        // מחזיר נתיב לקובץ פלט עבור כלי
        
        Args:
            tool_name: Name of the tool
            extension: File extension
            
        Returns:
            Path to output file
        """
        return os.path.join(self.scans_dir, f"{tool_name}_{self.target}.{extension}")
    
    def get_tool_path(self, tool_name):
        """
        Returns the path to a tool
        // מחזיר את הנתיב לכלי
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Path to the tool
        """
        return self.tool_paths.get(tool_name, tool_name)  # If not found, return the tool name itself
    
    def update_settings(self, new_settings):
        """
        Update configuration settings
        // עדכון הגדרות תצורה
        
        Args:
            new_settings: Dictionary of new settings to update
        """
        # Recursive update of settings
        self._update_dict_recursive(vars(self), new_settings)
    
    def _update_dict_recursive(self, target, source):
        """
        Recursively update a dictionary
        // עדכון רקורסיבי של מילון
        
        Args:
            target: Target dictionary to update
            source: Source dictionary to take updates from
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict_recursive(target[key], value)
            else:
                target[key] = value 
    
    def get_script_path(self, script_name):
        """
        Returns the path to a custom script
        // מחזיר את הנתיב לסקריפט מותאם אישית
        
        Args:
            script_name: Name of the script
            
        Returns:
            Path to the script
        """
        return self.script_paths.get(script_name)
    
    def set_gpt_api_key(self, api_key):
        """
        Set the GPT API key
        // הגדרת מפתח ה-API של GPT
        
        Args:
            api_key: The API key
        """
        self.gpt_settings["api_key"] = api_key
        os.environ["OPENAI_API_KEY"] = api_key  # Also save in environment
    
    def set_custom_prompt(self, prompt):
        """
        Set a custom prompt for GPT
        // הגדרת פרומפט מותאם אישית ל-GPT
        
        Args:
            prompt: The custom prompt
        """
        self.gpt_settings["custom_prompt"] = prompt
    
    def get_gpt_prompt(self) -> str:
        """
        Returns the GPT prompt to use for analysis
        // מחזיר את הפרומפט לשימוש עבור GPT לצורך אנליזה
        
        Returns:
            System prompt string
        """
        # Use custom prompt if it exists, otherwise use the system prompt
        return self.gpt_settings.get("custom_prompt") or self.gpt_settings.get("system_prompt", "")
    
    def get_gpt_api_key(self) -> str:
        """
        Returns the OpenAI API key from settings, environment variables or keyfile
        // מחזיר את מפתח ה-API של OpenAI מההגדרות, משתני סביבה או קובץ מפתח
        
        Returns:
            API key string or None if not found
        """
        # Check settings first
        api_key = self.gpt_settings.get('api_key')
        if api_key and len(api_key) > 10:
            return api_key
            
        # Check environment variable
        api_key = os.environ.get('OPENAI_API_KEY')
        if api_key and len(api_key) > 10:
            return api_key
            
        # Check for key file in home directory
        key_file = os.path.expanduser('~/.openai_api_key')
        if os.path.exists(key_file):
            try:
                with open(key_file, 'r') as f:
                    api_key = f.read().strip()
                if api_key and len(api_key) > 10:
                    return api_key
            except Exception:
                pass
                
        return None 