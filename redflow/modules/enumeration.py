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
                "vhosts": [],
                "downloaded_files": []  # Track downloaded files
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
            self.logger.info(f"Running gobuster against {target_url}")
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
                                    
                    self.logger.info(f"Found {len(web_info['directories'])} directories and {len(web_info['files'])} files")
            
            # Run nikto for vulnerability scanning
            nikto_output = self.config.get_output_file(f"nikto_{port}", "txt")
            
            self.logger.info(f"Running nikto vulnerability scan against {target_url}")
            cmd = ["nikto", "-h", target_url, "-o", nikto_output]
            
            # If HTTPS, add parameter to skip SSL verification
            if is_https:
                cmd.extend(["-ssl"])
            
            result = run_tool(cmd, timeout=600)
            
            if result["returncode"] == 0:
                self.logger.debug(f"Nikto results saved in: {nikto_output}")
                # Parse nikto results to find additional files or vulnerabilities
                if os.path.exists(nikto_output):
                    with open(nikto_output, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for line in lines:
                            # Extract file paths from nikto output
                            if "OSVDB" in line and ":" in line:
                                parts = line.split(":", 2)
                                if len(parts) > 2:
                                    message = parts[2].strip()
                                    # Extract paths found
                                    path_match = re.search(r'/([\w\-\.\/]+)', message)
                                    if path_match and path_match.group(0) not in web_info["files"]:
                                        web_info["files"].append(path_match.group(0))
            
            # Try to check for robots.txt and sitemap.xml
            common_files = ["robots.txt", "sitemap.xml", ".htaccess", "crossdomain.xml"]
            for file in common_files:
                file_url = f"{target_url}{file}"
                try:
                    resp = requests.get(file_url, verify=False, timeout=5)
                    if resp.status_code == 200:
                        file_path = f"/{file}"
                        if file_path not in web_info["files"]:
                            self.logger.info(f"Found common file: {file_path}")
                            web_info["files"].append(file_path)
                            
                            # Parse robots.txt for additional paths
                            if file == "robots.txt":
                                for line in resp.text.splitlines():
                                    if "Disallow:" in line:
                                        path = line.split("Disallow:", 1)[1].strip()
                                        if path and path not in web_info["files"] and path not in web_info["directories"]:
                                            if path.endswith("/"):
                                                web_info["directories"].append(path)
                                            else:
                                                web_info["files"].append(path)
                except:
                    pass
                
            # Check for interesting files in root directory
            interesting_paths = [
                "/backup", "/admin", "/login", "/config", "/dashboard", 
                "/wp-admin", "/wp-login.php", "/wp-config.php", "/config.php",
                "/administrator", "/phpmyadmin", "/secret"
            ]
            
            for path in interesting_paths:
                path_url = f"{target_url.rstrip('/')}{path}"
                try:
                    resp = requests.get(path_url, verify=False, timeout=5)
                    if resp.status_code != 404:
                        if path.endswith("/") or "." not in path:
                            if path not in web_info["directories"]:
                                self.logger.info(f"Found interesting directory: {path}")
                                web_info["directories"].append(path)
                        else:
                            if path not in web_info["files"]:
                                self.logger.info(f"Found interesting file: {path}")
                                web_info["files"].append(path)
                except:
                    pass
            
            # Initialize downloader and download interesting files if available
            if hasattr(self, 'downloader') and self.downloader:
                # Download interesting files found
                self._download_interesting_web_files(self.target, port, web_info)
                
            # Add this result to the list of web results
            web_results.append(web_info)
        
        self.results["web"] = web_results
        
        # Display information about downloaded files
        for web_result in web_results:
            downloaded = web_result.get("downloaded_files", [])
            if downloaded:
                port = web_result.get("port")
                protocol = web_result.get("protocol")
                self.logger.info(f"Downloaded {len(downloaded)} files from {protocol}://{self.target}:{port}")
                for dl_file in downloaded:
                    url = dl_file.get("url", "unknown")
                    local_path = dl_file.get("local_path", "unknown")
                    self.logger.info(f"  - {os.path.basename(local_path)} from {url}")
                    
                self.console.print(f"[green]Downloaded {len(downloaded)} files from {protocol}://{self.target}:{port}[/green]")
                self.console.print(f"Files saved in: {os.path.dirname(downloaded[0]['local_path'])}")
    
    def _download_interesting_web_files(self, host, port, web_info):
        """
        Download interesting files found during web enumeration
        
        Args:
            host (str): Web server host
            port (int): Web server port
            web_info (dict): Web information dictionary to update
        """
        # Create a specific directory for web downloads
        target_dir = self.downloader.create_directory_for_downloads(web_info["protocol"], port)
        
        # Define interesting file extensions to download
        interesting_extensions = [
            ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
            ".conf", ".config", ".ini", ".log", ".bak", ".backup",
            ".sql", ".db", ".xml", ".json", ".php", ".asp", ".jsp",
            ".zip", ".tar", ".gz", ".rar"
        ]
        
        protocol = web_info["protocol"]
        base_url = f"{protocol}://{host}:{port}"
        
        # Check each file
        for file_path in web_info["files"]:
            # Ensure path starts with /
            if not file_path.startswith("/"):
                file_path = "/" + file_path
                
            file_url = f"{base_url}{file_path}"
            filename = os.path.basename(file_path)
            extension = os.path.splitext(filename)[1].lower()
            
            # Only download files with interesting extensions or interesting names
            interesting_keywords = ["password", "admin", "user", "config", "backup", "secret", "key", "db"]
            
            if extension in interesting_extensions or any(keyword in filename.lower() for keyword in interesting_keywords):
                try:
                    self.logger.info(f"Downloading interesting web file: {file_url}")
                    
                    # Download the file
                    result = self.downloader.download_http_file(
                        url=file_url,
                        target_dir=target_dir,
                        verify=False
                    )
                    
                    if result:
                        web_info["downloaded_files"].append({
                            "url": file_url,
                            "local_path": result
                        })
                        
                except Exception as e:
                    self.logger.error(f"Error downloading web file {file_url}: {str(e)}")
                    
        # If we have found directories, also try to find index files inside them
        for dir_path in web_info["directories"]:
            # Ensure path starts with / and ends with /
            if not dir_path.startswith("/"):
                dir_path = "/" + dir_path
            if not dir_path.endswith("/"):
                dir_path = dir_path + "/"
                
            # Try common index files
            index_files = ["index.html", "index.php", "default.asp", "index.jsp", "default.html"]
            for index_file in index_files:
                file_url = f"{base_url}{dir_path}{index_file}"
                try:
                    resp = requests.head(file_url, verify=False, timeout=5)
                    if resp.status_code == 200:
                        self.logger.info(f"Found index file: {dir_path}{index_file}")
                        # Don't need to download index files specifically
                        break
                except:
                    pass
    
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
        self.console.print(f"\n[bold cyan]קבצים שהתגלו ב-{protocol}://{target}:{port_str}[/bold cyan]")
        
        all_paths = []
        
        if web_files:
            self.console.print(f"\n[bold green]קבצים ({len(web_files)}):[/bold green]")
            for i, file in enumerate(web_files, 1):
                self.console.print(f"  {i}. {file}")
                all_paths.append({"type": "file", "path": file})
        
        if web_dirs:
            self.console.print(f"\n[bold green]תיקיות ({len(web_dirs)}):[/bold green]")
            for i, directory in enumerate(web_dirs, len(web_files) + 1):
                self.console.print(f"  {i}. {directory}")
                all_paths.append({"type": "directory", "path": directory})
        
        # Ask user which files to download or directories to scan deeper
        self.console.print("\n[bold]בחר קבצים להורדה או תיקיות לסריקה עמוקה יותר:[/bold]")
        self.console.print("[bold]הזן מספרים מופרדים בפסיקים, 'all' לכל הקבצים, 'none' לדלג, או 'scan X' לסריקה עמוקה של תיקייה מספר X[/bold]")
        
        # Interactive mode requires input from user
        try:
            selection = input("> ").strip().lower()
            
            if selection == "all":
                indices = list(range(1, len(all_paths) + 1))
            elif selection == "none" or not selection:
                self.console.print("[yellow]לא נבחרו קבצים להורדה[/yellow]")
                return downloaded_files
            elif selection.startswith("scan "):
                # Parse directory to scan
                try:
                    dir_idx = int(selection.split("scan ")[1].strip())
                    if 1 <= dir_idx <= len(all_paths) and all_paths[dir_idx-1]["type"] == "directory":
                        dir_path = all_paths[dir_idx-1]["path"]
                        
                        # Perform recursive scan on this directory
                        self.console.print(f"[bold cyan]מבצע סריקה עמוקה של התיקייה: {dir_path}[/bold cyan]")
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
                            self.console.print(f"[green]נמצאו {len(new_files)} קבצים חדשים ו-{len(new_dirs)} תיקיות חדשות![/green]")
                            self.console.print("[yellow]הצגת רשימה מעודכנת של קבצים ותיקיות...[/yellow]")
                            return self.interactive_download_files(target, port_str, protocol)
                        else:
                            self.console.print("[yellow]לא נמצאו קבצים או תיקיות נוספים[/yellow]")
                            # Continue with the current list
                            return self.interactive_download_files(target, port_str, protocol)
                    else:
                        self.console.print("[red]מספר תיקייה לא חוקי. אנא בחר מספר תיקייה מהרשימה.[/red]")
                        return self.interactive_download_files(target, port_str, protocol)
                except ValueError:
                    self.console.print("[red]פורמט לא חוקי. השתמש ב-'scan X' כאשר X הוא מספר התיקייה.[/red]")
                    return self.interactive_download_files(target, port_str, protocol)
            else:
                # Parse user selection
                try:
                    indices = [int(idx.strip()) for idx in selection.split(",") if idx.strip()]
                except ValueError:
                    self.console.print("[red]קלט לא חוקי. אנא הזן מספרים מופרדים בפסיקים.[/red]")
                    return downloaded_files
            
            # Download selected files
            base_url = f"{protocol}://{target}:{port_str}"
            target_dir = os.path.join(self.config.output_dir, "downloads", f"{protocol}_{port_str}")
            os.makedirs(target_dir, exist_ok=True)
            
            self.console.print(f"[cyan]הקבצים יורדו אל: {target_dir}[/cyan]")
            
            total_success = 0
            total_failed = 0
            
            for idx in indices:
                if 1 <= idx <= len(all_paths):
                    item = all_paths[idx - 1]
                    path = item["path"]
                    item_type = item["type"]
                    
                    # Create the full URL
                    url = f"{base_url}{path}"
                    
                    if item_type == "file":
                        self.console.print(f"[bold]Downloading file: [blue]{path}[/blue]...[/bold]")
                        
                        try:
                            # Directly use requests for download to handle dependency issues
                            local_filename = os.path.join(target_dir, os.path.basename(path))
                            
                            # Ensure we have a filename
                            if not os.path.basename(path):
                                local_filename = os.path.join(target_dir, "index.html")
                            
                            # Download the file
                            import requests
                            response = requests.get(url, verify=False)
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
                        except Exception as e:
                            self.console.print(f"[red]Failed to download {path}: {str(e)}[/red]")
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
                                
                                # Check if file exists
                                response = requests.head(index_url, verify=False, timeout=5)
                                if response.status_code == 200:
                                    # Download the file
                                    dir_path = os.path.join(target_dir, os.path.basename(path.rstrip('/')))
                                    os.makedirs(dir_path, exist_ok=True)
                                    
                                    local_filename = os.path.join(dir_path, index)
                                    response = requests.get(index_url, verify=False)
                                    
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
                                            
                            if not dir_success:
                                self.console.print("[yellow]No index files found in directory. Try manually browsing to the directory.[/yellow]")
                                total_failed += 1
                        except Exception as e:
                            self.console.print(f"[red]Failed to check directory {path}: {str(e)}[/red]")
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
            
            return downloaded_files
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Download operation cancelled by user[/yellow]")
            return downloaded_files 

    def scan_directory_recursively(self, target, port, protocol, directory_path):
        """
        סריקה רקורסיבית של תיקייה לאיתור קבצים ותיקיות משנה
        
        Args:
            target (str): כתובת IP או שם מארח
            port (int או str): פורט של שירות האינטרנט
            protocol (str): פרוטוקול (http או https)
            directory_path (str): נתיב התיקייה לסריקה
            
        Returns:
            dict: מילון עם קבצים ותיקיות שנמצאו
        """
        result = {
            "directories": [],
            "files": []
        }
        
        self.console.print(f"[bold cyan]מבצע סריקה עמוקה של התיקייה: {directory_path}[/bold cyan]")
        
        # יצירת כתובת URL של היעד
        base_url = f"{protocol}://{target}:{port}"
        target_url = f"{base_url}{directory_path}"
        if not target_url.endswith('/'):
            target_url += '/'
        
        # ניסיון להפעיל סריקת gobuster מהירה על התיקייה
        try:
            # בחירת קובץ מילים לסריקת תיקיות
            wordlist = self.config.wordlist_paths.get("dirb_common")
            if not os.path.exists(wordlist):
                # אם קובץ המילים לא נמצא, ננסה למצוא אחר
                for key, wl_path in self.config.wordlist_paths.items():
                    if os.path.exists(wl_path) and "dir" in key:
                        wordlist = wl_path
                        break
            
            if not wordlist or not os.path.exists(wordlist):
                self.console.print("[yellow]לא נמצא קובץ מילים מתאים לסריקת התיקייה[/yellow]")
                return result
            
            self.console.print(f"[cyan]הפעלת סריקת gobuster על התיקייה {target_url}...[/cyan]")
            
            # יצירת קובץ פלט זמני
            output_file = os.path.join(self.config.output_dir, f"gobuster_recursive_{port}_{directory_path.replace('/', '_')}.txt")
            
            # בניית פקודת gobuster
            cmd = [
                "gobuster", "dir",
                "-u", target_url,
                "-w", wordlist,
                "-o", output_file,
                "-t", str(self.config.tool_settings["gobuster"]["threads"])
            ]
            
            # אם HTTPS, הוספת פרמטר לדילוג על אימות SSL
            if protocol == "https":
                cmd.extend(["-k"])
            
            # הפעלת gobuster
            import subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.console.print("[cyan]מבצע סריקה, אנא המתן...[/cyan]")
            stdout, stderr = process.communicate(timeout=120)  # הגבלה ל-2 דקות
            
            # ניתוח תוצאות
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    
                    for line in lines:
                        if line.startswith("/") or "(Status:" in line:
                            parts = line.split("(Status:")
                            if len(parts) > 1:
                                path = parts[0].strip()
                                status = parts[1].split(")")[0].strip()
                                
                                # נוסיף רק פריטים עם קודי סטטוס 2xx או 3xx
                                if status.startswith("2") or status.startswith("3"):
                                    full_path = directory_path
                                    if not full_path.endswith('/'):
                                        full_path += '/'
                                    if path.startswith('/'):
                                        path = path[1:]
                                    full_path += path
                                    
                                    if path.endswith("/"):
                                        result["directories"].append(full_path)
                                    else:
                                        result["files"].append(full_path)
                
                self.console.print(f"[green]נמצאו {len(result['directories'])} תיקיות ו-{len(result['files'])} קבצים בתיקיית {directory_path}[/green]")
        except Exception as e:
            self.console.print(f"[red]שגיאה בסריקת התיקייה {directory_path}: {str(e)}[/red]")
        
        return result 

    def find_vulnerabilities_with_searchsploit(self, service_name, version):
        """
        חיפוש פגיעויות אפשריות באמצעות searchsploit
        
        Args:
            service_name (str): שם השירות (למשל vsftpd, apache)
            version (str): גרסת השירות
            
        Returns:
            dict: מילון עם תוצאות החיפוש
        """
        self.console.print(f"[bold cyan]מחפש פגיעויות עבור {service_name} {version}...[/bold cyan]")
        
        results = {
            "service": service_name,
            "version": version,
            "vulnerabilities": [],
            "searchsploit_command": "",
            "raw_output": ""
        }
        
        # נקה את הגרסה ושם השירות לחיפוש מיטבי
        clean_version = re.sub(r'[^0-9.]', '', version)  # שמור רק מספרים ונקודות
        search_terms = []
        
        # יצירת מספר וריאציות לחיפוש
        if clean_version:
            # חיפוש לפי גרסה מדויקת
            search_terms.append(f"{service_name} {clean_version}")
            
            # חיפוש לפי גרסה ראשית בלבד
            major_version = clean_version.split('.')[0] if '.' in clean_version else clean_version
            search_terms.append(f"{service_name} {major_version}")
            
            # חיפוש לפי גרסה ראשית ומשנית
            if '.' in clean_version:
                parts = clean_version.split('.')
                if len(parts) >= 2:
                    major_minor = f"{parts[0]}.{parts[1]}"
                    search_terms.append(f"{service_name} {major_minor}")
        
        # הוסף חיפוש לפי שם השירות בלבד
        search_terms.append(service_name)
        
        # הרץ searchsploit עבור כל אחד מהחיפושים
        for search_term in search_terms:
            # בנה את פקודת searchsploit
            command = ["searchsploit", "--color", search_term]
            
            try:
                result = run_tool(command, timeout=30)
                output = result["stdout"]
                
                if result["returncode"] == 0 and "Exploits: No Results" not in output:
                    results["searchsploit_command"] = " ".join(command)
                    results["raw_output"] = output
                    
                    # פלט את התוצאות המלאות לקובץ זמני
                    output_file = os.path.join(self.config.output_dir, f"searchsploit_{service_name}_{clean_version}.txt")
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(output)
                    
                    # פרסור התוצאות
                    for line in output.splitlines():
                        # דלג על שורות כותרת או ריקות
                        if not line.strip() or "------" in line or "Exploit Title" in line:
                            continue
                        
                        # ניסיון לחלץ פרטי הפגיעות
                        try:
                            # נחלק לפי רווחים מרובים
                            parts = re.split(r'\s{2,}', line.strip())
                            if len(parts) >= 2:
                                vuln = {
                                    "title": parts[0].strip(),
                                    "path": parts[-1].strip() if len(parts) > 2 else "",
                                    "raw": line.strip()
                                }
                                
                                # בדוק אם מדובר ב-exploit חדש שלא נמצא כבר
                                if not any(v["title"] == vuln["title"] for v in results["vulnerabilities"]):
                                    results["vulnerabilities"].append(vuln)
                        except Exception as e:
                            self.logger.debug(f"שגיאה בפרסור שורת searchsploit: {str(e)}")
                    
                    # אם מצאנו תוצאות, הפסק את החיפוש
                    if results["vulnerabilities"]:
                        break
            
            except Exception as e:
                self.logger.error(f"שגיאה בהרצת searchsploit: {str(e)}")
        
        # הצג סיכום התוצאות
        if results["vulnerabilities"]:
            self.console.print(f"[green]נמצאו {len(results['vulnerabilities'])} פגיעויות אפשריות עבור {service_name} {version}![/green]")
        else:
            self.console.print(f"[yellow]לא נמצאו פגיעויות ידועות עבור {service_name} {version}[/yellow]")
        
        return results

    def prepare_exploit(self, exploit_path, target):
        """
        הכנת exploit להרצה
        
        Args:
            exploit_path (str): נתיב ה-exploit ב-searchsploit
            target (str): כתובת IP או שם מארח של המטרה
            
        Returns:
            dict: פרטי ה-exploit שהוכן
        """
        result = {
            "success": False,
            "exploit_path": exploit_path,
            "local_path": None,
            "exploit_type": None,
            "command": None,
            "error": None
        }
        
        self.console.print(f"[bold cyan]מכין את ה-exploit: {exploit_path}[/bold cyan]")
        
        try:
            # העתק את ה-exploit למערכת המקומית
            command = ["searchsploit", "-m", exploit_path]
            copy_result = run_tool(command, timeout=30)
            
            if copy_result["returncode"] != 0:
                result["error"] = f"שגיאה בהעתקת ה-exploit: {copy_result['stderr']}"
                return result
            
            # מצא את המיקום המקומי של הקובץ שהועתק
            output = copy_result["stdout"]
            local_path_match = re.search(r"Copied to: (.+)", output)
            
            if not local_path_match:
                result["error"] = "לא ניתן למצוא את נתיב ה-exploit המקומי"
                return result
            
            local_path = local_path_match.group(1).strip()
            result["local_path"] = local_path
            
            # זהה את סוג ה-exploit לפי סיומת הקובץ
            if local_path.endswith(".py"):
                result["exploit_type"] = "python"
                result["command"] = f"python {local_path} {target}"
            elif local_path.endswith(".rb"):
                result["exploit_type"] = "ruby"
                result["command"] = f"ruby {local_path} {target}"
            elif local_path.endswith(".c"):
                result["exploit_type"] = "c"
                # הכנת קובץ C להרצה דורשת קומפילציה
                compile_command = f"gcc {local_path} -o {local_path.replace('.c', '')}"
                run_command = f"{local_path.replace('.c', '')} {target}"
                result["command"] = f"{compile_command} && {run_command}"
            elif local_path.endswith(".sh"):
                result["exploit_type"] = "shell"
                result["command"] = f"bash {local_path} {target}"
            elif local_path.endswith(".php"):
                result["exploit_type"] = "php"
                result["command"] = f"php {local_path} {target}"
            else:
                result["exploit_type"] = "unknown"
                result["command"] = f"cat {local_path}"  # הצג את תוכן הקובץ אם לא ניתן לזהות את הסוג
            
            result["success"] = True
            self.console.print(f"[green]ה-exploit הועתק בהצלחה ל: {local_path}[/green]")
            
        except Exception as e:
            result["error"] = f"שגיאה בהכנת ה-exploit: {str(e)}"
            self.logger.error(f"שגיאה בהכנת ה-exploit {exploit_path}: {str(e)}")
        
        return result

    def interactive_exploit_menu(self, service_type, service_name, version, target=None):
        """
        תפריט אינטראקטיבי לחיפוש ובחירת exploits
        
        Args:
            service_type (str): סוג השירות (ftp, http, וכו')
            service_name (str): שם השירות (vsftpd, apache, וכו')
            version (str): גרסת השירות
            target (str, optional): כתובת IP או שם המארח
            
        Returns:
            bool: האם התהליך הושלם בהצלחה
        """
        if target is None:
            target = self.target

        self.console.print(f"[bold cyan]תפריט ניצול פגיעויות עבור {service_name} {version}[/bold cyan]")
        
        # חפש פגיעויות ב-searchsploit
        search_results = self.find_vulnerabilities_with_searchsploit(service_name, version)
        vulnerabilities = search_results.get("vulnerabilities", [])
        
        if not vulnerabilities:
            self.console.print("[yellow]לא נמצאו פגיעויות ידועות. נסה חיפוש ידני או שנה את מונחי החיפוש.[/yellow]")
            
            # הצע למשתמש לבצע חיפוש מותאם אישית
            self.console.print("[bold]האם תרצה לבצע חיפוש מותאם אישית ב-searchsploit?[/bold] (כן/לא)")
            custom_search = input("> ").strip().lower()
            
            if custom_search in ["כן", "yes", "y"]:
                self.console.print("[bold]הזן מונחי חיפוש (למשל: vsftpd 2.3.4):[/bold]")
                search_term = input("> ").strip()
                
                if search_term:
                    # הרץ את החיפוש המותאם אישית
                    command = ["searchsploit", "--color", search_term]
                    try:
                        result = run_tool(command, timeout=30)
                        self.console.print(result["stdout"])
                        
                        # בקש מהמשתמש להזין את נתיב ה-exploit המדויק אם מעוניין
                        self.console.print("[bold]הזן את נתיב ה-exploit (למשל: 49757.py) או הקש Enter לביטול:[/bold]")
                        exploit_path = input("> ").strip()
                        
                        if exploit_path:
                            # הכן את ה-exploit
                            exploit_info = self.prepare_exploit(exploit_path, target)
                            
                            if exploit_info["success"]:
                                # הצג הוראות הרצה
                                self.display_exploit_instructions(exploit_info, target)
                                return True
                    except Exception as e:
                        self.logger.error(f"שגיאה בהרצת חיפוש מותאם אישית: {str(e)}")
            
            return False
        
        # הצג את הפגיעויות שנמצאו
        self.console.print("\n[bold green]פגיעויות אפשריות:[/bold green]")
        for i, vuln in enumerate(vulnerabilities, 1):
            self.console.print(f"  {i}. [cyan]{vuln['title']}[/cyan]")
            if vuln['path']:
                self.console.print(f"     Path: {vuln['path']}")
        
        # בקש מהמשתמש לבחור exploit
        self.console.print("\n[bold]בחר מספר exploit להכנה או הקש Enter לביטול:[/bold]")
        selection = input("> ").strip()
        
        if not selection:
            self.console.print("[yellow]פעולה בוטלה.[/yellow]")
            return False
        
        try:
            selection_idx = int(selection)
            if 1 <= selection_idx <= len(vulnerabilities):
                selected_vuln = vulnerabilities[selection_idx - 1]
                
                # נתיב ה-exploit עשוי להיות מסוגים שונים
                exploit_path = selected_vuln["path"]
                
                # הכן את ה-exploit
                exploit_info = self.prepare_exploit(exploit_path, target)
                
                if exploit_info["success"]:
                    # הצג הוראות הרצה
                    self.display_exploit_instructions(exploit_info, target)
                    return True
                else:
                    self.console.print(f"[red]שגיאה בהכנת ה-exploit: {exploit_info['error']}[/red]")
            else:
                self.console.print("[red]בחירה לא חוקית.[/red]")
        except ValueError:
            self.console.print("[red]בחירה לא חוקית. אנא הזן מספר.[/red]")
        
        return False
    
    def display_exploit_instructions(self, exploit_info, target):
        """
        הצגת הוראות להרצת ה-exploit
        
        Args:
            exploit_info (dict): פרטי ה-exploit שהוכן
            target (str): כתובת IP או שם מארח של המטרה
        """
        self.console.print("\n[bold green]ה-exploit הוכן בהצלחה![/bold green]")
        self.console.print(f"[cyan]סוג ה-exploit: {exploit_info['exploit_type']}[/cyan]")
        self.console.print(f"[cyan]מיקום מקומי: {exploit_info['local_path']}[/cyan]")
        
        self.console.print("\n[bold yellow]הוראות הרצה:[/bold yellow]")
        
        if exploit_info["exploit_type"] == "unknown":
            self.console.print("[yellow]סוג ה-exploit לא זוהה. להלן תוכן הקובץ:[/yellow]")
            try:
                with open(exploit_info["local_path"], "r", errors="ignore") as f:
                    content = f.read(1000)  # הצג רק 1000 תווים ראשונים
                self.console.print(f"```\n{content}\n...\n```")
                self.console.print("[yellow]עליך לבדוק את הקובץ ולקבוע כיצד להשתמש בו.[/yellow]")
            except Exception as e:
                self.console.print(f"[red]שגיאה בקריאת תוכן הקובץ: {str(e)}[/red]")
        else:
            self.console.print(f"[green]להרצת ה-exploit, הפעל את הפקודה הבאה:[/green]")
            self.console.print(f"[bold white]{exploit_info['command']}[/bold white]")
            
            if exploit_info["exploit_type"] == "c":
                self.console.print("[yellow]שים לב: קובץ C דורש קומפילציה לפני ההרצה.[/yellow]")
            
            # שאל את המשתמש אם להריץ את ה-exploit
            self.console.print("\n[bold]האם תרצה להריץ את ה-exploit עכשיו?[/bold] (כן/לא)")
            run_exploit = input("> ").strip().lower()
            
            if run_exploit in ["כן", "yes", "y"]:
                self.console.print("\n[bold cyan]מריץ את ה-exploit...[/bold cyan]")
                try:
                    # הרץ את הפקודה
                    import subprocess
                    if exploit_info["exploit_type"] == "c":
                        # לקובצי C, נריץ קודם את הקומפילציה ואחריה את ההרצה
                        compile_cmd = exploit_info["command"].split("&&")[0].strip()
                        run_cmd = exploit_info["command"].split("&&")[1].strip()
                        
                        self.console.print(f"[cyan]קומפילציה: {compile_cmd}[/cyan]")
                        compile_process = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = compile_process.communicate()
                        
                        if compile_process.returncode == 0:
                            self.console.print("[green]קומפילציה הסתיימה בהצלחה.[/green]")
                            self.console.print(f"[cyan]הרצה: {run_cmd}[/cyan]")
                            run_process = subprocess.Popen(run_cmd, shell=True)
                            run_process.wait()
                        else:
                            self.console.print(f"[red]שגיאת קומפילציה: {stderr.decode('utf-8', errors='ignore')}[/red]")
                    else:
                        # לכל סוגי הקבצים האחרים, נריץ את הפקודה ישירות
                        process = subprocess.Popen(exploit_info["command"], shell=True)
                        process.wait()
                except Exception as e:
                    self.console.print(f"[red]שגיאה בהרצת ה-exploit: {str(e)}[/red]")
        
        self.console.print("\n[bold yellow]זכור:[/bold yellow]")
        self.console.print("[yellow]1. שימוש ב-exploits עלול לדרוש התאמות לתנאי הסביבה הספציפיים.[/yellow]")
        self.console.print("[yellow]2. ייתכן שיידרשו פרמטרים נוספים לחלק מה-exploits.[/yellow]")
        self.console.print("[yellow]3. בדוק תמיד את קוד ה-exploit לפני הרצה כדי להבין את פעולתו.[/yellow]")
    
    def find_vulnerabilities_with_searchsploit(self, service_name, version):
        """
        חיפוש פגיעויות אפשריות באמצעות searchsploit
        
        Args:
            service_name (str): שם השירות (למשל vsftpd, apache)
            version (str): גרסת השירות
            
        Returns:
            dict: מילון עם תוצאות החיפוש
        """
        self.console.print(f"[bold cyan]מחפש פגיעויות עבור {service_name} {version}...[/bold cyan]")
        
        results = {
            "service": service_name,
            "version": version,
            "vulnerabilities": [],
            "searchsploit_command": "",
            "raw_output": ""
        }
        
        # נקה את הגרסה ושם השירות לחיפוש מיטבי
        clean_version = re.sub(r'[^0-9.]', '', version)  # שמור רק מספרים ונקודות
        search_terms = []
        
        # יצירת מספר וריאציות לחיפוש
        if clean_version:
            # חיפוש לפי גרסה מדויקת
            search_terms.append(f"{service_name} {clean_version}")
            
            # חיפוש לפי גרסה ראשית בלבד
            major_version = clean_version.split('.')[0] if '.' in clean_version else clean_version
            search_terms.append(f"{service_name} {major_version}")
            
            # חיפוש לפי גרסה ראשית ומשנית
            if '.' in clean_version:
                parts = clean_version.split('.')
                if len(parts) >= 2:
                    major_minor = f"{parts[0]}.{parts[1]}"
                    search_terms.append(f"{service_name} {major_minor}")
        
        # הוסף חיפוש לפי שם השירות בלבד
        search_terms.append(service_name)
        
        # הרץ searchsploit עבור כל אחד מהחיפושים
        for search_term in search_terms:
            # בנה את פקודת searchsploit
            command = ["searchsploit", "--color", search_term]
            
            try:
                result = run_tool(command, timeout=30)
                output = result["stdout"]
                
                if result["returncode"] == 0 and "Exploits: No Results" not in output:
                    results["searchsploit_command"] = " ".join(command)
                    results["raw_output"] = output
                    
                    # פלט את התוצאות המלאות לקובץ זמני
                    output_file = os.path.join(self.config.output_dir, f"searchsploit_{service_name}_{clean_version}.txt")
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(output)
                    
                    # פרסור התוצאות
                    for line in output.splitlines():
                        # דלג על שורות כותרת או ריקות
                        if not line.strip() or "------" in line or "Exploit Title" in line:
                            continue
                        
                        # ניסיון לחלץ פרטי הפגיעות
                        try:
                            # נחלק לפי רווחים מרובים
                            parts = re.split(r'\s{2,}', line.strip())
                            if len(parts) >= 2:
                                vuln = {
                                    "title": parts[0].strip(),
                                    "path": parts[-1].strip() if len(parts) > 2 else "",
                                    "raw": line.strip()
                                }
                                
                                # בדוק אם מדובר ב-exploit חדש שלא נמצא כבר
                                if not any(v["title"] == vuln["title"] for v in results["vulnerabilities"]):
                                    results["vulnerabilities"].append(vuln)
                        except Exception as e:
                            self.logger.debug(f"שגיאה בפרסור שורת searchsploit: {str(e)}")
                    
                    # אם מצאנו תוצאות, הפסק את החיפוש
                    if results["vulnerabilities"]:
                        break
            
            except Exception as e:
                self.logger.error(f"שגיאה בהרצת searchsploit: {str(e)}")
        
        # הצג סיכום התוצאות
        if results["vulnerabilities"]:
            self.console.print(f"[green]נמצאו {len(results['vulnerabilities'])} פגיעויות אפשריות עבור {service_name} {version}![/green]")
        else:
            self.console.print(f"[yellow]לא נמצאו פגיעויות ידועות עבור {service_name} {version}[/yellow]")
        
        return results

    def prepare_exploit(self, exploit_path, target):
        """
        הכנת exploit להרצה
        
        Args:
            exploit_path (str): נתיב ה-exploit ב-searchsploit
            target (str): כתובת IP או שם מארח של המטרה
            
        Returns:
            dict: פרטי ה-exploit שהוכן
        """
        result = {
            "success": False,
            "exploit_path": exploit_path,
            "local_path": None,
            "exploit_type": None,
            "command": None,
            "error": None
        }
        
        self.console.print(f"[bold cyan]מכין את ה-exploit: {exploit_path}[/bold cyan]")
        
        try:
            # העתק את ה-exploit למערכת המקומית
            command = ["searchsploit", "-m", exploit_path]
            copy_result = run_tool(command, timeout=30)
            
            if copy_result["returncode"] != 0:
                result["error"] = f"שגיאה בהעתקת ה-exploit: {copy_result['stderr']}"
                return result
            
            # מצא את המיקום המקומי של הקובץ שהועתק
            output = copy_result["stdout"]
            local_path_match = re.search(r"Copied to: (.+)", output)
            
            if not local_path_match:
                result["error"] = "לא ניתן למצוא את נתיב ה-exploit המקומי"
                return result
            
            local_path = local_path_match.group(1).strip()
            result["local_path"] = local_path
            
            # זהה את סוג ה-exploit לפי סיומת הקובץ
            if local_path.endswith(".py"):
                result["exploit_type"] = "python"
                result["command"] = f"python {local_path} {target}"
            elif local_path.endswith(".rb"):
                result["exploit_type"] = "ruby"
                result["command"] = f"ruby {local_path} {target}"
            elif local_path.endswith(".c"):
                result["exploit_type"] = "c"
                # הכנת קובץ C להרצה דורשת קומפילציה
                compile_command = f"gcc {local_path} -o {local_path.replace('.c', '')}"
                run_command = f"{local_path.replace('.c', '')} {target}"
                result["command"] = f"{compile_command} && {run_command}"
            elif local_path.endswith(".sh"):
                result["exploit_type"] = "shell"
                result["command"] = f"bash {local_path} {target}"
            elif local_path.endswith(".php"):
                result["exploit_type"] = "php"
                result["command"] = f"php {local_path} {target}"
            else:
                result["exploit_type"] = "unknown"
                result["command"] = f"cat {local_path}"  # הצג את תוכן הקובץ אם לא ניתן לזהות את הסוג
            
            result["success"] = True
            self.console.print(f"[green]ה-exploit הועתק בהצלחה ל: {local_path}[/green]")
            
        except Exception as e:
            result["error"] = f"שגיאה בהכנת ה-exploit: {str(e)}"
            self.logger.error(f"שגיאה בהכנת ה-exploit {exploit_path}: {str(e)}")
        
        return result

    def interactive_exploit_menu(self, service_type, service_name, version, target=None):
        """
        תפריט אינטראקטיבי לחיפוש ובחירת exploits
        
        Args:
            service_type (str): סוג השירות (ftp, http, וכו')
            service_name (str): שם השירות (vsftpd, apache, וכו')
            version (str): גרסת השירות
            target (str, optional): כתובת IP או שם המארח
            
        Returns:
            bool: האם התהליך הושלם בהצלחה
        """
        if target is None:
            target = self.target

        self.console.print(f"[bold cyan]תפריט ניצול פגיעויות עבור {service_name} {version}[/bold cyan]")
        
        # חפש פגיעויות ב-searchsploit
        search_results = self.find_vulnerabilities_with_searchsploit(service_name, version)
        vulnerabilities = search_results.get("vulnerabilities", [])
        
        if not vulnerabilities:
            self.console.print("[yellow]לא נמצאו פגיעויות ידועות. נסה חיפוש ידני או שנה את מונחי החיפוש.[/yellow]")
            
            # הצע למשתמש לבצע חיפוש מותאם אישית
            self.console.print("[bold]האם תרצה לבצע חיפוש מותאם אישית ב-searchsploit?[/bold] (כן/לא)")
            custom_search = input("> ").strip().lower()
            
            if custom_search in ["כן", "yes", "y"]:
                self.console.print("[bold]הזן מונחי חיפוש (למשל: vsftpd 2.3.4):[/bold]")
                search_term = input("> ").strip()
                
                if search_term:
                    # הרץ את החיפוש המותאם אישית
                    command = ["searchsploit", "--color", search_term]
                    try:
                        result = run_tool(command, timeout=30)
                        self.console.print(result["stdout"])
                        
                        # בקש מהמשתמש להזין את נתיב ה-exploit המדויק אם מעוניין
                        self.console.print("[bold]הזן את נתיב ה-exploit (למשל: 49757.py) או הקש Enter לביטול:[/bold]")
                        exploit_path = input("> ").strip()
                        
                        if exploit_path:
                            # הכן את ה-exploit
                            exploit_info = self.prepare_exploit(exploit_path, target)
                            
                            if exploit_info["success"]:
                                # הצג הוראות הרצה
                                self.display_exploit_instructions(exploit_info, target)
                                return True
                    except Exception as e:
                        self.logger.error(f"שגיאה בהרצת חיפוש מותאם אישית: {str(e)}")
            
            return False
        
        # הצג את הפגיעויות שנמצאו
        self.console.print("\n[bold green]פגיעויות אפשריות:[/bold green]")
        for i, vuln in enumerate(vulnerabilities, 1):
            self.console.print(f"  {i}. [cyan]{vuln['title']}[/cyan]")
            if vuln['path']:
                self.console.print(f"     Path: {vuln['path']}")
        
        # בקש מהמשתמש לבחור exploit
        self.console.print("\n[bold]בחר מספר exploit להכנה או הקש Enter לביטול:[/bold]")
        selection = input("> ").strip()
        
        if not selection:
            self.console.print("[yellow]פעולה בוטלה.[/yellow]")
            return False
        
        try:
            selection_idx = int(selection)
            if 1 <= selection_idx <= len(vulnerabilities):
                selected_vuln = vulnerabilities[selection_idx - 1]
                
                # נתיב ה-exploit עשוי להיות מסוגים שונים
                exploit_path = selected_vuln["path"]
                
                # הכן את ה-exploit
                exploit_info = self.prepare_exploit(exploit_path, target)
                
                if exploit_info["success"]:
                    # הצג הוראות הרצה
                    self.display_exploit_instructions(exploit_info, target)
                    return True
                else:
                    self.console.print(f"[red]שגיאה בהכנת ה-exploit: {exploit_info['error']}[/red]")
            else:
                self.console.print("[red]בחירה לא חוקית.[/red]")
        except ValueError:
            self.console.print("[red]בחירה לא חוקית. אנא הזן מספר.[/red]")
        
        return False
    
    def display_exploit_instructions(self, exploit_info, target):
        """
        הצגת הוראות להרצת ה-exploit
        
        Args:
            exploit_info (dict): פרטי ה-exploit שהוכן
            target (str): כתובת IP או שם מארח של המטרה
        """
        self.console.print("\n[bold green]ה-exploit הוכן בהצלחה![/bold green]")
        self.console.print(f"[cyan]סוג ה-exploit: {exploit_info['exploit_type']}[/cyan]")
        self.console.print(f"[cyan]מיקום מקומי: {exploit_info['local_path']}[/cyan]")
        
        self.console.print("\n[bold yellow]הוראות הרצה:[/bold yellow]")
        
        if exploit_info["exploit_type"] == "unknown":
            self.console.print("[yellow]סוג ה-exploit לא זוהה. להלן תוכן הקובץ:[/yellow]")
            try:
                with open(exploit_info["local_path"], "r", errors="ignore") as f:
                    content = f.read(1000)  # הצג רק 1000 תווים ראשונים
                self.console.print(f"```\n{content}\n...\n```")
                self.console.print("[yellow]עליך לבדוק את הקובץ ולקבוע כיצד להשתמש בו.[/yellow]")
            except Exception as e:
                self.console.print(f"[red]שגיאה בקריאת תוכן הקובץ: {str(e)}[/red]")
        else:
            self.console.print(f"[green]להרצת ה-exploit, הפעל את הפקודה הבאה:[/green]")
            self.console.print(f"[bold white]{exploit_info['command']}[/bold white]")
            
            if exploit_info["exploit_type"] == "c":
                self.console.print("[yellow]שים לב: קובץ C דורש קומפילציה לפני ההרצה.[/yellow]")
            
            # שאל את המשתמש אם להריץ את ה-exploit
            self.console.print("\n[bold]האם תרצה להריץ את ה-exploit עכשיו?[/bold] (כן/לא)")
            run_exploit = input("> ").strip().lower()
            
            if run_exploit in ["כן", "yes", "y"]:
                self.console.print("\n[bold cyan]מריץ את ה-exploit...[/bold cyan]")
                try:
                    # הרץ את הפקודה
                    import subprocess
                    if exploit_info["exploit_type"] == "c":
                        # לקובצי C, נריץ קודם את הקומפילציה ואחריה את ההרצה
                        compile_cmd = exploit_info["command"].split("&&")[0].strip()
                        run_cmd = exploit_info["command"].split("&&")[1].strip()
                        
                        self.console.print(f"[cyan]קומפילציה: {compile_cmd}[/cyan]")
                        compile_process = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = compile_process.communicate()
                        
                        if compile_process.returncode == 0:
                            self.console.print("[green]קומפילציה הסתיימה בהצלחה.[/green]")
                            self.console.print(f"[cyan]הרצה: {run_cmd}[/cyan]")
                            run_process = subprocess.Popen(run_cmd, shell=True)
                            run_process.wait()
                        else:
                            self.console.print(f"[red]שגיאת קומפילציה: {stderr.decode('utf-8', errors='ignore')}[/red]")
                    else:
                        # לכל סוגי הקבצים האחרים, נריץ את הפקודה ישירות
                        process = subprocess.Popen(exploit_info["command"], shell=True)
                        process.wait()
                except Exception as e:
                    self.console.print(f"[red]שגיאה בהרצת ה-exploit: {str(e)}[/red]")
        
        self.console.print("\n[bold yellow]זכור:[/bold yellow]")
        self.console.print("[yellow]1. שימוש ב-exploits עלול לדרוש התאמות לתנאי הסביבה הספציפיים.[/yellow]")
        self.console.print("[yellow]2. ייתכן שיידרשו פרמטרים נוספים לחלק מה-exploits.[/yellow]")
        self.console.print("[yellow]3. בדוק תמיד את קוד ה-exploit לפני הרצה כדי להבין את פעולתו.[/yellow]")
    
    def find_vulnerabilities_with_searchsploit(self, service_name, version):
        """
        חיפוש פגיעויות אפשריות באמצעות searchsploit
        
        Args:
            service_name (str): שם השירות (למשל vsftpd, apache)
            version (str): גרסת השירות
            
        Returns:
            dict: מילון עם תוצאות החיפוש
        """
        self.console.print(f"[bold cyan]מחפש פגיעויות עבור {service_name} {version}...[/bold cyan]")
        
        results = {
            "service": service_name,
            "version": version,
            "vulnerabilities": [],
            "searchsploit_command": "",
            "raw_output": ""
        }
        
        # נקה את הגרסה ושם השירות לחיפוש מיטבי
        clean_version = re.sub(r'[^0-9.]', '', version)  # שמור רק מספרים ונקודות
        search_terms = []
        
        # יצירת מספר וריאציות לחיפוש
        if clean_version:
            # חיפוש לפי גרסה מדויקת
            search_terms.append(f"{service_name} {clean_version}")
            
            # חיפוש לפי גרסה ראשית בלבד
            major_version = clean_version.split('.')[0] if '.' in clean_version else clean_version
            search_terms.append(f"{service_name} {major_version}")
            
            # חיפוש לפי גרסה ראשית ומשנית
            if '.' in clean_version:
                parts = clean_version.split('.')
                if len(parts) >= 2:
                    major_minor = f"{parts[0]}.{parts[1]}"
                    search_terms.append(f"{service_name} {major_minor}")
        
        # הוסף חיפוש לפי שם השירות בלבד
        search_terms.append(service_name)
        
        # הרץ searchsploit עבור כל אחד מהחיפושים
        for search_term in search_terms:
            # בנה את פקודת searchsploit
            command = ["searchsploit", "--color", search_term]
            
            try:
                result = run_tool(command, timeout=30)
                output = result["stdout"]
                
                if result["returncode"] == 0 and "Exploits: No Results" not in output:
                    results["searchsploit_command"] = " ".join(command)
                    results["raw_output"] = output
                    
                    # פלט את התוצאות המלאות לקובץ זמני
                    output_file = os.path.join(self.config.output_dir, f"searchsploit_{service_name}_{clean_version}.txt")
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(output)
                    
                    # פרסור התוצאות
                    for line in output.splitlines():
                        # דלג על שורות כותרת או ריקות
                        if not line.strip() or "------" in line or "Exploit Title" in line:
                            continue
                        
                        # ניסיון לחלץ פרטי הפגיעות
                        try:
                            # נחלק לפי רווחים מרובים
                            parts = re.split(r'\s{2,}', line.strip())
                            if len(parts) >= 2:
                                vuln = {
                                    "title": parts[0].strip(),
                                    "path": parts[-1].strip() if len(parts) > 2 else "",
                                    "raw": line.strip()
                                }
                                
                                # בדוק אם מדובר ב-exploit חדש שלא נמצא כבר
                                if not any(v["title"] == vuln["title"] for v in results["vulnerabilities"]):
                                    results["vulnerabilities"].append(vuln)
                        except Exception as e:
                            self.logger.debug(f"שגיאה בפרסור שורת searchsploit: {str(e)}")
                    
                    # אם מצאנו תוצאות, הפסק את החיפוש
                    if results["vulnerabilities"]:
                        break
            
            except Exception as e:
                self.logger.error(f"שגיאה בהרצת searchsploit: {str(e)}")
        
        # הצג סיכום התוצאות
        if results["vulnerabilities"]:
            self.console.print(f"[green]נמצאו {len(results['vulnerabilities'])} פגיעויות אפשריות עבור {service_name} {version}![/green]")
        else:
            self.console.print(f"[yellow]לא נמצאו פגיעויות ידועות עבור {service_name} {version}[/yellow]")
        
        return results

    def prepare_exploit(self, exploit_path, target):
        """
        הכנת exploit להרצה
        
        Args:
            exploit_path (str): נתיב ה-exploit ב-searchsploit
            target (str): כתובת IP או שם מארח של המטרה
            
        Returns:
            dict: פרטי ה-exploit שהוכן
        """
        result = {
            "success": False,
            "exploit_path": exploit_path,
            "local_path": None,
            "exploit_type": None,
            "command": None,
            "error": None
        }
        
        self.console.print(f"[bold cyan]מכין את ה-exploit: {exploit_path}[/bold cyan]")
        
        try:
            # העתק את ה-exploit למערכת המקומית
            command = ["searchsploit", "-m", exploit_path]
            copy_result = run_tool(command, timeout=30)
            
            if copy_result["returncode"] != 0:
                result["error"] = f"שגיאה בהעתקת ה-exploit: {copy_result['stderr']}"
                return result
            
            # מצא את המיקום המקומי של הקובץ שהועתק
            output = copy_result["stdout"]
            local_path_match = re.search(r"Copied to: (.+)", output)
            
            if not local_path_match:
                result["error"] = "לא ניתן למצוא את נתיב ה-exploit המקומי"
                return result
            
            local_path = local_path_match.group(1).strip()
            result["local_path"] = local_path
            
            # זהה את סוג ה-exploit לפי סיומת הקובץ
            if local_path.endswith(".py"):
                result["exploit_type"] = "python"
                result["command"] = f"python {local_path} {target}"
            elif local_path.endswith(".rb"):
                result["exploit_type"] = "ruby"
                result["command"] = f"ruby {local_path} {target}"
            elif local_path.endswith(".c"):
                result["exploit_type"] = "c"
                # הכנת קובץ C להרצה דורשת קומפילציה
                compile_command = f"gcc {local_path} -o {local_path.replace('.c', '')}"
                run_command = f"{local_path.replace('.c', '')} {target}"
                result["command"] = f"{compile_command} && {run_command}"
            elif local_path.endswith(".sh"):
                result["exploit_type"] = "shell"
                result["command"] = f"bash {local_path} {target}"
            elif local_path.endswith(".php"):
                result["exploit_type"] = "php"
                result["command"] = f"php {local_path} {target}"
            else:
                result["exploit_type"] = "unknown"
                result["command"] = f"cat {local_path}"  # הצג את תוכן הקובץ אם לא ניתן לזהות את הסוג
            
            result["success"] = True
            self.console.print(f"[green]ה-exploit הועתק בהצלחה ל: {local_path}[/green]")
            
        except Exception as e:
            result["error"] = f"שגיאה בהכנת ה-exploit: {str(e)}"
            self.logger.error(f"שגיאה בהכנת ה-exploit {exploit_path}: {str(e)}")
        
        return result

    def interactive_exploit_menu(self, service_type, service_name, version, target=None):
        """
        תפריט אינטראקטיבי לחיפוש ובחירת exploits
        
        Args:
            service_type (str): סוג השירות (ftp, http, וכו')
            service_name (str): שם השירות (vsftpd, apache, וכו')
            version (str): גרסת השירות
            target (str, optional): כתובת IP או שם המארח
            
        Returns:
            bool: האם התהליך הושלם בהצלחה
        """
        if target is None:
            target = self.target

        self.console.print(f"[bold cyan]תפריט ניצול פגיעויות עבור {service_name} {version}[/bold cyan]")
        
        # חפש פגיעויות ב-searchsploit
        search_results = self.find_vulnerabilities_with_searchsploit(service_name, version)
        vulnerabilities = search_results.get("vulnerabilities", [])
        
        if not vulnerabilities:
            self.console.print("[yellow]לא נמצאו פגיעויות ידועות. נסה חיפוש ידני או שנה את מונחי החיפוש.[/yellow]")
            
            # הצע למשתמש לבצע חיפוש מותאם אישית
            self.console.print("[bold]האם תרצה לבצע חיפוש מותאם אישית ב-searchsploit?[/bold] (כן/לא)")
            custom_search = input("> ").strip().lower()
            
            if custom_search in ["כן", "yes", "y"]:
                self.console.print("[bold]הזן מונחי חיפוש (למשל: vsftpd 2.3.4):[/bold]")
                search_term = input("> ").strip()
                
                if search_term:
                    # הרץ את החיפוש המותאם אישית
                    command = ["searchsploit", "--color", search_term]
                    try:
                        result = run_tool(command, timeout=30)
                        self.console.print(result["stdout"])
                        
                        # בקש מהמשתמש להזין את נתיב ה-exploit המדויק אם מעוניין
                        self.console.print("[bold]הזן את נתיב ה-exploit (למשל: 49757.py) או הקש Enter לביטול:[/bold]")
                        exploit_path = input("> ").strip()
                        
                        if exploit_path:
                            # הכן את ה-exploit
                            exploit_info = self.prepare_exploit(exploit_path, target)
                            
                            if exploit_info["success"]:
                                # הצג הוראות הרצה
                                self.display_exploit_instructions(exploit_info, target)
                                return True
                    except Exception as e:
                        self.logger.error(f"שגיאה בהרצת חיפוש מותאם אישית: {str(e)}")
            
            return False
        
        # הצג את הפגיעויות שנמצאו
        self.console.print("\n[bold green]פגיעויות אפשריות:[/bold green]")
        for i, vuln in enumerate(vulnerabilities, 1):
            self.console.print(f"  {i}. [cyan]{vuln['title']}[/cyan]")
            if vuln['path']:
                self.console.print(f"     Path: {vuln['path']}")
        
        # בקש מהמשתמש לבחור exploit
        self.console.print("\n[bold]בחר מספר exploit להכנה או הקש Enter לביטול:[/bold]")
        selection = input("> ").strip()
        
        if not selection:
            self.console.print("[yellow]פעולה בוטלה.[/yellow]")
            return False
        
        try:
            selection_idx = int(selection)
            if 1 <= selection_idx <= len(vulnerabilities):
                selected_vuln = vulnerabilities[selection_idx - 1]
                
                # נתיב ה-exploit עשוי להיות מסוגים שונים
                exploit_path = selected_vuln["path"]
                
                # הכן את ה-exploit
                exploit_info = self.prepare_exploit(exploit_path, target)
                
                if exploit_info["success"]:
                    # הצג הוראות הרצה
                    self.display_exploit_instructions(exploit_info, target)
                    return True
                else:
                    self.console.print(f"[red]שגיאה בהכנת ה-exploit: {exploit_info['error']}[/red]")
            else:
                self.console.print("[red]בחירה לא חוקית.[/red]")
        except ValueError:
            self.console.print("[red]בחירה לא חוקית. אנא הזן מספר.[/red]")
        
        return False
    
    def display_exploit_instructions(self, exploit_info, target):
        """
        הצגת הוראות להרצת ה-exploit
        
        Args:
            exploit_info (dict): פרטי ה-exploit שהוכן
            target (str): כתובת IP או שם מארח של המטרה
        """
        self.console.print("\n[bold green]ה-exploit הוכן בהצלחה![/bold green]")
        self.console.print(f"[cyan]סוג ה-exploit: {exploit_info['exploit_type']}[/cyan]")
        self.console.print(f"[cyan]מיקום מקומי: {exploit_info['local_path']}[/cyan]")
        
        self.console.print("\n[bold yellow]הוראות הרצה:[/bold yellow]")
        
        if exploit_info["exploit_type"] == "unknown":
            self.console.print("[yellow]סוג ה-exploit לא זוהה. להלן תוכן הקובץ:[/yellow]")
            try:
                with open(exploit_info["local_path"], "r", errors="ignore") as f:
                    content = f.read(1000)  # הצג רק 1000 תווים ראשונים
                self.console.print(f"```\n{content}\n...\n```")
                self.console.print("[yellow]עליך לבדוק את הקובץ ולקבוע כיצד להשתמש בו.[/yellow]")
            except Exception as e:
                self.console.print(f"[red]שגיאה בקריאת תוכן הקובץ: {str(e)}[/red]")
        else:
            self.console.print(f"[green]להרצת ה-exploit, הפעל את הפקודה הבאה:[/green]")
            self.console.print(f"[bold white]{exploit_info['command']}[/bold white]")
            
            if exploit_info["exploit_type"] == "c":
                self.console.print("[yellow]שים לב: קובץ C דורש קומפילציה לפני ההרצה.[/yellow]")
            
            # שאל את המשתמש אם להריץ את ה-exploit
            self.console.print("\n[bold]האם תרצה להריץ את ה-exploit עכשיו?[/bold] (כן/לא)")
            run_exploit = input("> ").strip().lower()
            
            if run_exploit in ["כן", "yes", "y"]:
                self.console.print("\n[bold cyan]מריץ את ה-exploit...[/bold cyan]")
                try:
                    # הרץ את הפקודה
                    import subprocess
                    if exploit_info["exploit_type"] == "c":
                        # לקובצי C, נריץ קודם את הקומפילציה ואחריה את ההרצה
                        compile_cmd = exploit_info["command"].split("&&")[0].strip()
                        run_cmd = exploit_info["command"].split("&&")[1].strip()
                        
                        self.console.print(f"[cyan]קומפילציה: {compile_cmd}[/cyan]")
                        compile_process = subprocess.Popen(compile_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = compile_process.communicate()
                        
                        if compile_process.returncode == 0:
                            self.console.print("[green]קומפילציה הסתיימה בהצלחה.[/green]")
                            self.console.print(f"[cyan]הרצה: {run_cmd}[/cyan]")
                            run_process = subprocess.Popen(run_cmd, shell=True)
                            run_process.wait()
                        else:
                            self.console.print(f"[red]שגיאת קומפילציה: {stderr.decode('utf-8', errors='ignore')}[/red]")
                    else:
                        # לכל סוגי הקבצים האחרים, נריץ את הפקודה ישירות
                        process = subprocess.Popen(exploit_info["command"], shell=True)
                        process.wait()
                except Exception as e:
                    self.console.print(f"[red]שגיאה בהרצת ה-exploit: {str(e)}[/red]")
        
        self.console.print("\n[bold yellow]זכור:[/bold yellow]")
        self.console.print("[yellow]1. שימוש ב-exploits עלול לדרוש התאמות לתנאי הסביבה הספציפיים.[/yellow]")
        self.console.print("[yellow]2. ייתכן שיידרשו פרמטרים נוספים לחלק מה-exploits.[/yellow]")
        self.console.print("[yellow]3. בדוק תמיד את קוד ה-exploit לפני הרצה כדי להבין את פעולתו.[/yellow]")