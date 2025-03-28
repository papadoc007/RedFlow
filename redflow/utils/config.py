"""
Configuration module for managing RedFlow settings
"""

import os
import json
import yaml
from pathlib import Path


class Config:
    """Class for managing program settings"""
    
    def __init__(self, args, project_dir):
        """
        Initialize configuration object
        
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
        
        # Project directory paths
        self.scans_dir = os.path.join(self.output_dir, "scans")
        self.logs_dir = os.path.join(self.output_dir, "logs")
        self.summaries_dir = os.path.join(self.output_dir, "summaries")
        self.scripts_dir = os.path.join(self.output_dir, "scripts")
        
        # Create directories if they don't exist
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.summaries_dir, exist_ok=True)
        os.makedirs(self.scripts_dir, exist_ok=True)
        
        # Load default settings
        self.load_default_settings()
        
        # Load settings from external config file if it exists
        self.load_config_file()
        
        # Check for required tools and warn if missing
        self.check_required_tools()
        
        # Save scan metadata
        self.save_metadata()
    
    def load_default_settings(self):
        """Load default settings and configuration files"""
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
            "wafw00f": "/usr/bin/wafw00f",
            "searchsploit": "/usr/bin/searchsploit",
            "msfconsole": "/usr/bin/msfconsole"
        }
        
        # Paths to custom scripts
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
            "max_exploits_to_suggest": 10,
            "attempt_meterpreter": True,  # Prefer Meterpreter over regular shells
            "use_full_search": True,      # Enable both exact and general searches
            "force_bash": True,           # Try to upgrade to bash shells when possible
            "auto_configure_exploits": True  # Automatically configure exploits with target info
        }
        
        # Settings for different tools
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
        
        # GPT-related settings
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
    
    def check_required_tools(self):
        """Check if required tools are available and log warnings if not"""
        required_tools = {
            "searchsploit": "SearchSploit is required for exploit suggestions",
            "msfconsole": "Metasploit is required for automated exploitation"
        }
        
        missing_tools = []
        
        for tool, description in required_tools.items():
            tool_path = self.tool_paths.get(tool, "")
            if not os.path.exists(tool_path):
                missing_tools.append(f"{tool}: {description}")
        
        if missing_tools:
            print("\n[WARNING] Missing required tools:")
            for tool in missing_tools:
                print(f"  - {tool}")
            print("\nSome functionality may be limited. Please install the missing tools.")
    
    def load_config_file(self):
        """Load settings from external configuration file"""
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
                            self.exploitation.update(config_data['exploitation'])
                        else:
                            # Default exploitation settings with new options
                            self.exploitation = {
                                "metasploit_auto_detect": True,
                                "auto_update_searchsploit": True,
                                "exploitdb_path": "/usr/share/exploitdb",
                                "max_exploits_to_suggest": 10,
                                "attempt_meterpreter": True,
                                "use_full_search": True,
                                "force_bash": True,
                                "auto_configure_exploits": True
                            }
            except Exception as e:
                print(f"Error loading configuration file: {str(e)}")
    
    def save_metadata(self):
        """Save metadata about the current scan"""
        metadata = {
            "target": self.target,
            "mode": self.mode,
            "timestamp": self._get_timestamp(),
            "gpt_enabled": self.use_gpt,
            "gpt_model": self.gpt_model,
            "scan_vulns": self.scan_vulns
        }
        
        metadata_file = os.path.join(self.output_dir, "metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)
    
    def _get_timestamp(self):
        """Get current timestamp in YYYYMMDD_HHMMSS format"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def get_output_file(self, tool_name, extension="txt"):
        """
        Get output file path for a tool
        
        Args:
            tool_name: Name of the tool
            extension: File extension (default: txt)
            
        Returns:
            Path to the output file
        """
        filename = f"{tool_name}_{self._get_timestamp()}.{extension}"
        return os.path.join(self.scans_dir, filename)
    
    def get_tool_path(self, tool_name):
        """
        Get path to a tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Path to the tool executable
        """
        return self.tool_paths.get(tool_name, tool_name)
    
    def update_settings(self, new_settings):
        """
        Update settings with new values
        
        Args:
            new_settings: Dictionary with new settings
        """
        if 'tool_paths' in new_settings:
            self._update_dict_recursive(self.tool_paths, new_settings['tool_paths'])
            
        if 'script_paths' in new_settings:
            self._update_dict_recursive(self.script_paths, new_settings['script_paths'])
            
        if 'tool_settings' in new_settings:
            self._update_dict_recursive(self.tool_settings, new_settings['tool_settings'])
            
        if 'gpt_settings' in new_settings:
            self._update_dict_recursive(self.gpt_settings, new_settings['gpt_settings'])
    
    def _update_dict_recursive(self, target, source):
        """
        Update target dictionary with values from source dictionary recursively
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with new values
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict_recursive(target[key], value)
            else:
                target[key] = value
    
    def get_script_path(self, script_name):
        """
        Get path to a script
        
        Args:
            script_name: Name of the script
            
        Returns:
            Path to the script file
        """
        if script_name in self.script_paths:
            return self.script_paths[script_name]
        else:
            return os.path.join(self.scripts_dir, f"{script_name}.py")
    
    def set_gpt_api_key(self, api_key):
        """
        Set the OpenAI API key
        
        Args:
            api_key: OpenAI API key
        """
        self.gpt_settings["api_key"] = api_key
        os.environ["OPENAI_API_KEY"] = api_key
    
    def set_custom_prompt(self, prompt):
        """
        Set a custom GPT prompt
        
        Args:
            prompt: Custom prompt text
        """
        self.gpt_settings["custom_prompt"] = prompt
    
    def get_gpt_prompt(self) -> str:
        """
        Get the GPT prompt (custom or default)
        
        Returns:
            GPT prompt
        """
        if self.gpt_settings.get("custom_prompt"):
            return self.gpt_settings["custom_prompt"]
        else:
            return self.gpt_settings["system_prompt"]
    
    def get_gpt_api_key(self) -> str:
        """
        Get the OpenAI API key
        
        Returns:
            OpenAI API key
        """
        # Try to get API key from config
        api_key = self.gpt_settings.get("api_key", "")
        
        # If not found, try environment variable
        if not api_key:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            
        # If not in environment, try to read from ~/.openai_api_key
        if not api_key:
            key_file = os.path.expanduser("~/.openai_api_key")
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'r') as f:
                        api_key = f.read().strip()
                except Exception as e:
                    print(f"Error reading API key file: {e}")
                    
        return api_key 