"""
Module for downloading files from target hosts using various protocols
"""

import os
import requests
import ftplib
from urllib.parse import urlparse, unquote
from requests.exceptions import RequestException
import logging
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Try to import FTPHost from ftputil, but provide fallback if not available
try:
    from ftputil import FTPHost
    FTPUTIL_AVAILABLE = True
except ImportError:
    FTPUTIL_AVAILABLE = False

class FileDownloader:
    """
    Class for downloading files from target hosts using various protocols
    """
    
    def __init__(self, output_dir, logger=None, console=None):
        """
        Initialize the file downloader
        
        Args:
            output_dir (str): Directory to save downloaded files
            logger (logging.Logger, optional): Logger instance
            console (rich.console.Console, optional): Console instance for output
        """
        self.output_dir = output_dir
        self.logger = logger or logging.getLogger(__name__)
        self.console = console
        
        # Create downloads directory if it doesn't exist
        self.download_dir = os.path.join(output_dir, "downloads")
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
            
        # Check if ftputil is available and log warning if not
        if not FTPUTIL_AVAILABLE and logger:
            self.logger.warning("ftputil package is not installed. FTP downloads will use basic functionality.")
            if console:
                console.print("[yellow]Warning: ftputil package is not installed. Install it with 'pip install ftputil' for better FTP support.[/yellow]")
    
    def download_http_file(self, url, target_dir=None, auth=None, verify=False):
        """
        Download a file from HTTP/HTTPS
        
        Args:
            url (str): URL of the file to download
            target_dir (str, optional): Directory to save the file, defaults to downloads directory
            auth (tuple, optional): (username, password) for authentication
            verify (bool, optional): Verify SSL certificates
            
        Returns:
            str: Path to the downloaded file or None if download failed
        """
        target_dir = target_dir or self.download_dir
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
            
        # Parse URL to get the filename
        parsed_url = urlparse(url)
        filename = os.path.basename(unquote(parsed_url.path))
        
        if not filename:
            self.logger.warning(f"Could not determine filename from URL: {url}")
            filename = "downloaded_file"
            
        local_path = os.path.join(target_dir, filename)
        
        try:
            self.logger.info(f"Downloading {url} to {local_path}")
            
            if self.console:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[blue]Downloading file..."),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=self.console
                ) as progress:
                    task = progress.add_task("Downloading", total=1)
                    
                    with requests.get(url, stream=True, auth=auth, verify=verify) as response:
                        response.raise_for_status()
                        with open(local_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        progress.update(task, completed=1)
            else:
                with requests.get(url, auth=auth, verify=verify) as response:
                    response.raise_for_status()
                    with open(local_path, 'wb') as f:
                        f.write(response.content)
                        
            self.logger.info(f"Successfully downloaded {url} to {local_path}")
            return local_path
            
        except RequestException as e:
            self.logger.error(f"Error downloading file from {url}: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error downloading file from {url}: {str(e)}")
            return None
            
    def download_ftp_file(self, host, remote_path, username="anonymous", password="anonymous@example.com", target_dir=None, port=21):
        """
        Download a file from FTP server
        
        Args:
            host (str): FTP server hostname or IP
            remote_path (str): Path to the file on the FTP server
            username (str, optional): FTP username
            password (str, optional): FTP password
            target_dir (str, optional): Directory to save the file, defaults to downloads directory
            port (int, optional): FTP port
            
        Returns:
            str: Path to the downloaded file or None if download failed
        """
        # Ensure host is a string
        host = str(host)
        
        target_dir = target_dir or self.download_dir
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
            
        filename = os.path.basename(remote_path)
        local_path = os.path.join(target_dir, filename)
        
        try:
            self.logger.info(f"Downloading FTP file {remote_path} from {host} to {local_path}")
            
            # Use different methods based on whether ftputil is available
            if FTPUTIL_AVAILABLE:
                # Advanced FTP client with ftputil
                if self.console:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[blue]Downloading FTP file..."),
                        BarColumn(),
                        TaskProgressColumn(),
                        console=self.console
                    ) as progress:
                        task = progress.add_task("Downloading", total=1)
                        
                        with FTPHost(host, username, password, port=port) as ftp:
                            ftp.download(remote_path, local_path)
                        progress.update(task, completed=1)
                else:
                    with FTPHost(host, username, password, port=port) as ftp:
                        ftp.download(remote_path, local_path)
            else:
                # Basic FTP client (fallback)
                if self.console:
                    self.console.print("[yellow]Using basic FTP functionality. Install ftputil for better FTP support.[/yellow]")
                
                with ftplib.FTP() as ftp:
                    ftp.connect(host, port)
                    ftp.login(username, password)
                    
                    with open(local_path, 'wb') as f:
                        ftp.retrbinary(f"RETR {remote_path}", f.write)
                    
            self.logger.info(f"Successfully downloaded {remote_path} from {host} to {local_path}")
            return local_path
            
        except ftplib.all_errors as e:
            self.logger.error(f"FTP error downloading {remote_path} from {host}: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error downloading FTP file: {str(e)}")
            return None
            
    def download_file(self, url_or_path, protocol="http", host=None, auth=None, target_dir=None, **kwargs):
        """
        General method to download a file using the appropriate protocol
        
        Args:
            url_or_path (str): URL or file path to download
            protocol (str): Protocol to use (http, https, ftp)
            host (str, optional): Host for FTP protocol
            auth (tuple, optional): (username, password) for authentication
            target_dir (str, optional): Directory to save the file
            **kwargs: Additional arguments for specific protocol methods
            
        Returns:
            str: Path to the downloaded file or None if download failed
        """
        protocol = protocol.lower()
        
        if protocol in ["http", "https"]:
            return self.download_http_file(
                url=url_or_path,
                target_dir=target_dir,
                auth=auth,
                verify=kwargs.get("verify", False)
            )
        elif protocol == "ftp":
            if not host:
                self.logger.error("Host is required for FTP downloads")
                return None
            
            # Ensure host is a string
            host = str(host)
                
            # Parse username and password from auth
            username = "anonymous"
            password = "anonymous@example.com"
            
            if auth:
                username, password = auth
                
            return self.download_ftp_file(
                host=host,
                remote_path=url_or_path,
                username=username,
                password=password,
                target_dir=target_dir,
                port=kwargs.get("port", 21)
            )
        else:
            self.logger.error(f"Unsupported protocol: {protocol}")
            return None
            
    def create_directory_for_downloads(self, service_type, port):
        """
        Create a directory structure for organizing downloads
        
        Args:
            service_type (str): Type of service (ftp, http, etc.)
            port (int): Port number
            
        Returns:
            str: Path to the created directory
        """
        dir_path = os.path.join(self.download_dir, f"{service_type}_{port}")
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        return dir_path 