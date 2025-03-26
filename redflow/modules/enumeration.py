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
        
        # Get the web service results for the specified port
        web_files = []
        web_dirs = []
        
        if isinstance(self.results["web"], list):
            for web_service in self.results["web"]:
                if str(web_service.get("port", "")) == port_str and web_service.get("protocol", "") == protocol:
                    web_files = web_service.get("files", [])
                    web_dirs = web_service.get("directories", [])
                    break
        
        if not web_files and not web_dirs:
            self.console.print("[yellow]No files or directories discovered on this port[/yellow]")
            return downloaded_files
        
        # Initialize downloader if not present
        if not hasattr(self, 'downloader'):
            from redflow.utils.downloader import FileDownloader
            self.downloader = FileDownloader(self.config.output_dir, self.logger, self.console)
        
        # Display available files
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
        
        # Ask user which files to download
        self.console.print("\n[bold]Enter the numbers of files/directories to download (comma-separated, 'all' for all files, or 'none' to skip):[/bold]")
        
        # Interactive mode requires input from user
        try:
            selection = input("> ").strip().lower()
            
            if selection == "all":
                indices = list(range(1, len(all_paths) + 1))
            elif selection == "none" or not selection:
                self.console.print("[yellow]No files selected for download[/yellow]")
                return downloaded_files
            else:
                # Parse user selection
                try:
                    indices = [int(idx.strip()) for idx in selection.split(",") if idx.strip()]
                except ValueError:
                    self.console.print("[red]Invalid input. Please enter numbers separated by commas.[/red]")
                    return downloaded_files
            
            # Download selected files
            base_url = f"{protocol}://{target}:{port_str}"
            
            for idx in indices:
                if 1 <= idx <= len(all_paths):
                    item = all_paths[idx - 1]
                    path = item["path"]
                    item_type = item["type"]
                    
                    # Create the full URL
                    url = f"{base_url}{path}"
                    
                    if item_type == "file":
                        self.console.print(f"[bold]Downloading file: [blue]{path}[/blue]...[/bold]")
                        result = self.downloader.download_http_file(
                            url=url,
                            target_dir=None,  # Use default directory
                            verify=False
                        )
                        
                        if result:
                            downloaded_files.append(result)
                            self.console.print(f"[green]Downloaded to:[/green] {result}")
                        else:
                            self.console.print(f"[red]Failed to download {path}[/red]")
                    else:  # directory
                        self.console.print(f"[bold]Checking directory: [blue]{path}[/blue]...[/bold]")
                        self.console.print("[yellow]Note: Downloading directories is not fully implemented yet. You might want to navigate manually.[/yellow]")
                        # Future enhancement: Implement directory crawling and downloading
                else:
                    self.console.print(f"[red]Invalid selection: {idx}[/red]")
            
            if downloaded_files:
                self.console.print(f"\n[green]Successfully downloaded {len(downloaded_files)} files[/green]")
                download_dir = os.path.dirname(downloaded_files[0]) if downloaded_files else None
                if download_dir:
                    self.console.print(f"Files saved in: {download_dir}")
            else:
                self.console.print("[yellow]No files were successfully downloaded[/yellow]")
            
            return downloaded_files
                
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Download operation cancelled by user[/yellow]")
            return downloaded_files 