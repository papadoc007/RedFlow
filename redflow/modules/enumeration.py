"""
Module for performing service enumeration
// מודול לביצוע תשאול שירותים
"""

import os
import re
import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from redflow.utils.logger import get_module_logger
from redflow.utils.helpers import run_tool


class Enumeration:
    """Class for performing service enumeration // מחלקה לביצוע תשאול שירותים"""
    
    def __init__(self, config, logger, console):
        """
        Initialize enumeration module
        // אתחול מודול האנומרציה
        
        Args:
            config: Configuration object
            logger: Logger instance
            console: Console instance
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("Enumeration", logger)
        self.target = config.target
        self.results = {
            "web": {},
            "smb": {},
            "ftp": {},
            "ssh": {},
            "database": {}
        }
    
    def run(self, services):
        """
        Run appropriate service enumeration based on identified services
        // הפעלת תשאול שירותים מתאים בהתאם לשירותים שזוהו
        
        Args:
            services: List of identified services
            
        Returns:
            Enumeration results
        """
        self.logger.info(f"Starting service enumeration for {self.target}")
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            # Perform enumeration according to identified service types
            service_types = self._group_services_by_type(services)
            
            # FTP enumeration
            if "ftp" in service_types:
                ftp_task = progress.add_task("[cyan]Performing FTP enumeration...", total=1)
                self._enumerate_ftp(service_types["ftp"])
                progress.update(ftp_task, completed=1)
            
            # SMB/Windows enumeration
            if "smb" in service_types or "microsoft-ds" in service_types:
                smb_task = progress.add_task("[cyan]Performing SMB/Windows enumeration...", total=1)
                smb_services = service_types.get("smb", []) + service_types.get("microsoft-ds", [])
                self._enumerate_smb(smb_services)
                progress.update(smb_task, completed=1)
            
            # Web service enumeration
            if "http" in service_types or "https" in service_types:
                web_task = progress.add_task("[cyan]Performing Web service enumeration...", total=1)
                web_services = service_types.get("http", []) + service_types.get("https", [])
                self._enumerate_web(web_services)
                progress.update(web_task, completed=1)
            
            # SSH enumeration
            if "ssh" in service_types:
                ssh_task = progress.add_task("[cyan]Performing SSH enumeration...", total=1)
                self._enumerate_ssh(service_types["ssh"])
                progress.update(ssh_task, completed=1)
            
            # Database enumeration
            db_services = []
            for db_type in ["mysql", "postgresql", "mssql", "oracle"]:
                if db_type in service_types:
                    db_services.extend(service_types[db_type])
            
            if db_services:
                db_task = progress.add_task("[cyan]Performing database enumeration...", total=1)
                self._enumerate_databases(db_services)
                progress.update(db_task, completed=1)
        
        # After all enumerations are completed
        self._show_results_summary()
        
        return self.results
    
    def _group_services_by_type(self, services):
        """
        Group services by their type
        // קיבוץ שירותים לפי סוג
        
        Args:
            services: List of identified services
            
        Returns:
            Dictionary of service types with lists of services
        """
        service_types = {}
        
        for service in services:
            service_name = service["name"].lower()
            
            if service_name not in service_types:
                service_types[service_name] = []
            
            service_types[service_name].append(service)
        
        # Log found service types
        if service_types:
            self.logger.info(f"Service types identified: {', '.join(service_types.keys())}")
        
        return service_types
    
    def _enumerate_ftp(self, ftp_services):
        """
        Perform FTP service enumeration
        // ביצוע תשאול שירותי FTP
        
        Args:
            ftp_services: List of FTP services
        """
        self.logger.info(f"Performing FTP enumeration for {self.target}")
        
        ftp_results = {
            "anonymous_access": False,
            "version": "",
            "directories": [],
            "port": ftp_services[0]["port"] if ftp_services else 21
        }
        
        # Check anonymous access
        for ftp_service in ftp_services:
            port = ftp_service["port"]
            version = ftp_service.get("version", "")
            ftp_results["version"] = version
            
            # Try anonymous login
            output_file = self.config.get_output_file(f"ftp_anon_{port}", "txt")
            
            cmd = ["nmap", "--script", "ftp-anon", "-p", str(port), self.target, "-oN", output_file]
            
            result = run_tool(cmd)
            
            if result["returncode"] == 0:
                self.logger.debug(f"Anonymous FTP login check results saved in: {output_file}")
                
                # Analyze the results
                for line in result["stdout"].splitlines():
                    if "Anonymous FTP login allowed" in line:
                        ftp_results["anonymous_access"] = True
                        self.logger.info(f"Anonymous access granted to FTP on port {port}")
                        break
            
            # If anonymous access is granted, try to enumerate directories
            if ftp_results["anonymous_access"]:
                dirs_file = self.config.get_output_file(f"ftp_dirs_{port}", "txt")
                
                # You can use other tools like wget or curl with FTP requests
                cmd = ["nmap", "--script", "ftp-ls", "-p", str(port), self.target, "-oN", dirs_file]
                
                result = run_tool(cmd)
                
                if result["returncode"] == 0:
                    self.logger.debug(f"Directory enumeration results saved in: {dirs_file}")
                    
                    # Analyze the results
                    for line in result["stdout"].splitlines():
                        if "|" in line and "ftp-ls" in line:
                            dir_match = re.search(r"\s+(/\S+)", line)
                            if dir_match:
                                ftp_results["directories"].append(dir_match.group(1))
        
        self.results["ftp"] = ftp_results
    
    def _enumerate_smb(self, smb_services):
        """
        Perform SMB/Windows enumeration
        // ביצוע תשאול שירותי SMB/Windows
        
        Args:
            smb_services: List of SMB services
        """
        self.logger.info(f"Performing SMB/Windows enumeration for {self.target}")
        
        smb_results = {
            "version": "",
            "os": "",
            "computer_name": "",
            "domain": "",
            "shares": [],
            "users": [],
            "sessions": [],
            "port": smb_services[0]["port"] if smb_services else 445
        }
        
        for smb_service in smb_services:
            port = smb_service["port"]
            version = smb_service.get("version", "")
            smb_results["version"] = version
            
            # Run enum4linux
            output_file = self.config.get_output_file("enum4linux", "txt")
            
            cmd = ["enum4linux", "-a", self.target]
            
            result = run_tool(cmd, output_file=output_file)
            
            if result["returncode"] == 0:
                self.logger.debug(f"enum4linux results saved in: {output_file}")
                
                # Analyze the results
                stdout = result["stdout"]
                
                # Extract hostname
                hostname_match = re.search(r"NetBIOS computer name:\s*(\S+)", stdout)
                if hostname_match:
                    smb_results["computer_name"] = hostname_match.group(1)
                
                # Extract domain
                domain_match = re.search(r"Workgroup\s*/\s*Domain:\s*(\S+)", stdout)
                if domain_match:
                    smb_results["domain"] = domain_match.group(1)
                
                # Extract operating system
                os_match = re.search(r"OS:\s*(.+)", stdout)
                if os_match:
                    smb_results["os"] = os_match.group(1).strip()
                
                # Extract shares
                shares = []
                for line in stdout.splitlines():
                    share_match = re.search(r"Mapping: OK, Listing: OK\s*(\S+)", line)
                    if share_match:
                        shares.append(share_match.group(1))
                smb_results["shares"] = shares
                
                # Extract users
                users = []
                for line in stdout.splitlines():
                    user_match = re.search(r"user:\[(\S+)\]", line)
                    if user_match:
                        users.append(user_match.group(1))
                smb_results["users"] = users
            
            # Run SMB scripts
            nmap_output = self.config.get_output_file("nmap_smb", "txt")
            
            cmd = ["nmap", "--script", "smb-os-discovery,smb-enum-shares,smb-enum-users", "-p", str(port), self.target, "-oN", nmap_output]
            
            result = run_tool(cmd)
            
            if result["returncode"] == 0:
                self.logger.debug(f"nmap SMB scripts results saved in: {nmap_output}")
        
        self.results["smb"] = smb_results
    
    def _enumerate_web(self, web_services):
        """
        Perform Web service enumeration
        // ביצוע תשאול שירותי Web
        
        Args:
            web_services: List of Web services
        """
        self.logger.info(f"Performing Web enumeration for {self.target}")
        
        web_results = []
        
        for web_service in web_services:
            port = web_service["port"]
            is_https = web_service["name"].lower() == "https"
            protocol = "https" if is_https else "http"
            
            web_info = {
                "port": port,
                "protocol": protocol,
                "directories": [],
                "files": [],
                "tech": [],
                "vhosts": []
            }
            
            # Run gobuster to discover hidden directories and pages
            output_file = self.config.get_output_file(f"gobuster_{port}", "txt")
            
            # Create URL
            target_url = f"{protocol}://{self.target}:{port}/"
            
            # Select wordlist
            wordlist = self.config.wordlist_paths.get("dirb_common")
            if not os.path.exists(wordlist):
                # If wordlist not found, try to find another one
                for key, wl_path in self.config.wordlist_paths.items():
                    if os.path.exists(wl_path) and "dir" in key:
                        wordlist = wl_path
                        break
            
            if not wordlist or not os.path.exists(wordlist):
                self.logger.warning("No suitable wordlist found for gobuster, skipping")
                continue
            
            # Run gobuster
            cmd = [
                "gobuster", "dir",
                "-u", target_url,
                "-w", wordlist,
                "-o", output_file,
                "-t", str(self.config.tool_settings["gobuster"]["threads"])
            ]
            
            # If HTTPS, add parameter to skip SSL verification
            if is_https:
                cmd.extend(["-k"])
            
            result = run_tool(cmd, timeout=600)  # Longer runtime
            
            if result["returncode"] == 0:
                self.logger.debug(f"Gobuster results saved in: {output_file}")
                
                # Parse results
                if os.path.exists(output_file):
                    with open(output_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                        
                        for line in lines:
                            if line.startswith("/"):
                                path = line.split()[0].strip()
                                if path.endswith("/"):
                                    web_info["directories"].append(path)
                                else:
                                    web_info["files"].append(path)
            
            # Run nikto for vulnerability scanning
            nikto_output = self.config.get_output_file(f"nikto_{port}", "txt")
            
            cmd = ["nikto", "-h", target_url, "-o", nikto_output]
            
            result = run_tool(cmd, timeout=600)
            
            if result["returncode"] == 0:
                self.logger.debug(f"Nikto results saved in: {nikto_output}")
            
            web_results.append(web_info)
        
        self.results["web"] = web_results
    
    def _enumerate_ssh(self, ssh_services):
        """
        Perform SSH service enumeration
        // ביצוע תשאול שירותי SSH
        
        Args:
            ssh_services: List of SSH services
        """
        self.logger.info(f"Performing SSH enumeration for {self.target}")
        
        ssh_results = {
            "version": "",
            "auth_methods": [],
            "algorithms": [],
            "weak_algorithms": False,
            "port": ssh_services[0]["port"] if ssh_services else 22
        }
        
        for ssh_service in ssh_services:
            port = ssh_service["port"]
            version = ssh_service.get("version", "")
            ssh_results["version"] = version
            
            # Check authentication methods and weaknesses
            output_file = self.config.get_output_file(f"ssh_audit_{port}", "txt")
            
            cmd = ["nmap", "--script", "ssh-auth-methods,ssh2-enum-algos", "-p", str(port), self.target, "-oN", output_file]
            
            result = run_tool(cmd)
            
            if result["returncode"] == 0:
                self.logger.debug(f"SSH audit results saved in: {output_file}")
                
                # Parse results
                stdout = result["stdout"]
                
                # Extract authentication methods
                for line in stdout.splitlines():
                    if "ssh-auth-methods" in line and "publickey" in line:
                        methods = re.findall(r"(\w+)", line)
                        ssh_results["auth_methods"] = [m for m in methods if m in ["password", "publickey", "keyboard-interactive"]]
                
                # Extract algorithms
                algos = []
                for line in stdout.splitlines():
                    if "ssh2-enum-algos" in line and "encryption_algorithms" in line:
                        algo_match = re.search(r"encryption_algorithms:(.+)", line)
                        if algo_match:
                            algo_str = algo_match.group(1).strip()
                            algos = [a.strip() for a in algo_str.split(",")]
                            ssh_results["algorithms"] = algos
                
                # Check for weak algorithms
                weak_algos = ["arcfour", "blowfish", "3des", "des"]
                for algo in ssh_results.get("algorithms", []):
                    if any(weak in algo.lower() for weak in weak_algos):
                        ssh_results["weak_algorithms"] = True
                        break
        
        self.results["ssh"] = ssh_results
    
    def _enumerate_databases(self, db_services):
        """
        Perform database enumeration
        // ביצוע תשאול מסדי נתונים
        
        Args:
            db_services: List of database services
        """
        self.logger.info(f"Performing database enumeration for {self.target}")
        
        db_results = {}
        
        for db_service in db_services:
            port = db_service["port"]
            service_name = db_service["service"].lower()
            version = db_service.get("version", "")
            
            db_info = {
                "port": port,
                "type": service_name,
                "version": version,
                "default_credentials": False,
                "accessible": False
            }
            
            # Run nmap scripts specific to database type
            nmap_script = ""
            
            if "mysql" in service_name:
                nmap_script = "mysql-info,mysql-empty-password,mysql-enum,mysql-brute"
            elif "postgresql" in service_name or "postgres" in service_name:
                nmap_script = "pgsql-info,pgsql-brute"
            elif "mssql" in service_name:
                nmap_script = "ms-sql-info,ms-sql-empty-password,ms-sql-brute"
            elif "oracle" in service_name:
                nmap_script = "oracle-brute,oracle-enum-users"
            
            if nmap_script:
                output_file = self.config.get_output_file(f"db_{service_name}_{port}", "txt")
                
                cmd = ["nmap", "--script", nmap_script, "-p", str(port), self.target, "-oN", output_file]
                
                result = run_tool(cmd)
                
                if result["returncode"] == 0:
                    self.logger.debug(f"Database {service_name} results saved in: {output_file}")
                    
                    # Parse results
                    stdout = result["stdout"]
                    
                    # Check for access
                    if "success" in stdout.lower() or "identified" in stdout.lower():
                        db_info["accessible"] = True
                    
                    # Check for empty or default credentials
                    if "empty-password" in stdout.lower() or "default.credentials" in stdout.lower():
                        db_info["default_credentials"] = True
            
            # Add only if we found information about the database
            if db_info["type"] not in db_results:
                db_results[db_info["type"]] = []
            
            db_results[db_info["type"]].append(db_info)
        
        self.results["database"] = db_results
    
    def _show_results_summary(self):
        """
        Display summary of enumeration results
        // הצגת סיכום תוצאות התשאול
        """
        self.logger.info("Displaying enumeration results summary")
        
        self.console.print("\n[bold green]Service Enumeration Summary:[/bold green]")
        
        # FTP summary
        if self.results["ftp"]:
            ftp_info = self.results["ftp"]
            anon_access = "Yes" if ftp_info.get("anonymous_access", False) else "No"
            dirs_count = len(ftp_info.get("directories", []))
            
            self.console.print(f"[cyan]FTP (Port {ftp_info.get('port')}):[/cyan]")
            self.console.print(f"  Anonymous access: {anon_access}")
            self.console.print(f"  Directories found: {dirs_count}")
        
        # SMB summary
        if self.results["smb"]:
            smb_info = self.results["smb"]
            shares_count = len(smb_info.get("shares", []))
            users_count = len(smb_info.get("users", []))
            
            self.console.print(f"[cyan]SMB (Port {smb_info.get('port')}):[/cyan]")
            self.console.print(f"  Computer name: {smb_info.get('computer_name', 'Unknown')}")
            self.console.print(f"  Domain: {smb_info.get('domain', 'Unknown')}")
            self.console.print(f"  Operating System: {smb_info.get('os', 'Unknown')}")
            self.console.print(f"  Shares found: {shares_count}")
            self.console.print(f"  Users found: {users_count}")
        
        # Web summary
        if self.results["web"]:
            for web_info in self.results["web"]:
                protocol = web_info.get("protocol", "http")
                port = web_info.get("port")
                dirs_count = len(web_info.get("directories", []))
                files_count = len(web_info.get("files", []))
                
                self.console.print(f"[cyan]Web ({protocol} on port {port}):[/cyan]")
                self.console.print(f"  Directories found: {dirs_count}")
                self.console.print(f"  Files found: {files_count}")
        
        # SSH summary
        if self.results["ssh"]:
            ssh_info = self.results["ssh"]
            auth_methods = ", ".join(ssh_info.get("auth_methods", ["Unknown"]))
            weak_algos = "Yes" if ssh_info.get("weak_algorithms", False) else "No"
            
            self.console.print(f"[cyan]SSH (Port {ssh_info.get('port')}):[/cyan]")
            self.console.print(f"  Version: {ssh_info.get('version', 'Unknown')}")
            self.console.print(f"  Authentication methods: {auth_methods}")
            self.console.print(f"  Weak algorithms: {weak_algos}")
        
        # Database summary
        if self.results["database"]:
            for db_type, db_instances in self.results["database"].items():
                for db in db_instances:
                    port = db.get("port")
                    accessible = "Yes" if db.get("accessible", False) else "No"
                    default_creds = "Yes" if db.get("default_credentials", False) else "No"
                    
                    self.console.print(f"[cyan]Database {db_type} (Port {port}):[/cyan]")
                    self.console.print(f"  Version: {db.get('version', 'Unknown')}")
                    self.console.print(f"  Accessible: {accessible}")
                    self.console.print(f"  Default credentials: {default_creds}")
        
        self.console.print("")  # Extra space 