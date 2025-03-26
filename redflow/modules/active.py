"""
Module for performing active scanning
// מודול לביצוע סריקה אקטיבית
"""

import os
import re
import time
import json
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from redflow.utils.logger import get_module_logger
from redflow.utils.helpers import run_tool


class ActiveRecon:
    """Class for performing active reconnaissance // מחלקה לביצוע סריקה אקטיבית"""
    
    def __init__(self, config, logger, console):
        """
        Initialize active reconnaissance module
        // אתחול מודול הסריקה האקטיבית
        
        Args:
            config: Configuration object
            logger: Logger instance
            console: Console instance
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("ActiveRecon", logger)
        self.target = config.target
        self.results = {
            "open_ports": [],
            "discovered_services": [],
            "os_detection": {},
            "traceroute": {},
            "nmap_vulns": []
        }
    
    def run(self):
        """
        Run all active scanning tasks
        // הפעלת כל הסריקות האקטיביות
        
        Returns:
            Active scanning results
        """
        self.logger.info(f"Starting active scan for {self.target}")
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            # First do a quick scan to identify open ports
            quick_scan_task = progress.add_task("[cyan]Performing quick port scan...", total=1)
            self._perform_quick_portscan()
            progress.update(quick_scan_task, completed=1)
            
            # Detailed service scan
            service_scan_task = progress.add_task("[cyan]Performing detailed service scan...", total=1)
            self._perform_service_scan()
            progress.update(service_scan_task, completed=1)
            
            # Run NSE Scripts
            vuln_scan_task = progress.add_task("[cyan]Performing vulnerability scan...", total=1)
            self._perform_vuln_scan()
            progress.update(vuln_scan_task, completed=1)
        
        # After all scans are completed
        self._show_results_summary()
        
        return self.results
    
    def _perform_quick_portscan(self):
        """
        Perform quick SYN scan to identify open ports
        // ביצוע סריקת SYN מהירה לזיהוי פורטים פתוחים
        """
        self.logger.info("Starting quick port scan")
        
        # Create output file path
        quick_scan_output = self.config.get_output_file("nmap_quick", "xml")
        
        # Use Nmap for quick scan
        command = [
            self.config.get_tool_path("nmap"),
            "-sS",                           # SYN Scan
            "-T4",                           # Aggressive timing
            "--min-rate", "1000",            # Minimum rate of packets
            "-p-",                           # All ports
            "--open",                        # Only show open ports
            "-oX", quick_scan_output,        # XML output
            self.target
        ]
        
        # Run Nmap with timeout
        scan_results = run_tool(command, self.logger, timeout=900)
        
        if scan_results['returncode'] != 0:
            self.logger.error("Quick port scan failed")
            return
        
        # Parse the XML output to get open ports
        if os.path.exists(quick_scan_output):
            try:
                with open(quick_scan_output, 'r') as f:
                    xml_content = f.read()
                
                # Extract open ports using regex
                port_matches = re.findall(r'portid="(\d+)".*state="open"', xml_content)
                open_ports = list(set(port_matches))  # Remove duplicates
                
                if open_ports:
                    self.logger.info(f"Found {len(open_ports)} open ports: {', '.join(open_ports)}")
                    self.results["open_ports"] = open_ports
                else:
                    self.logger.warning("No open ports found")
            except Exception as e:
                self.logger.error(f"Error parsing Nmap output: {str(e)}")
        else:
            self.logger.error("Nmap quick scan output file not found")
    
    def _perform_service_scan(self):
        """
        Perform detailed service scan on identified open ports
        // ביצוע סריקת שירותים מפורטת על הפורטים שזוהו
        """
        self.logger.info("Starting detailed service scan")
        
        if not self.results["open_ports"]:
            self.logger.warning("No open ports to scan for services")
            return
            
        # Create output file path
        service_scan_output = self.config.get_output_file("nmap_services", "xml")
        
        # Join the open ports into a comma-separated string
        port_str = ",".join(self.results["open_ports"])
        
        # Use Nmap for service scanning
        command = [
            self.config.get_tool_path("nmap"),
            "-sV",                           # Service detection
            "-sC",                           # Default scripts
            "-O",                            # OS detection
            "--osscan-guess",                # Guess OS aggressively
            "-p", port_str,                  # Scan specific ports
            "-oX", service_scan_output,      # XML output
            self.target
        ]
        
        # Run Nmap with timeout
        scan_results = run_tool(command, self.logger, timeout=1200)
        
        if scan_results['returncode'] != 0:
            self.logger.error("Service scan failed")
            return
            
        # Parse the XML output
        if os.path.exists(service_scan_output):
            try:
                with open(service_scan_output, 'r') as f:
                    xml_content = f.read()
                
                # Extract service information
                service_matches = re.findall(r'portid="(\d+)".*name="([^"]*)".*product="([^"]*)".*version="([^"]*)"', xml_content)
                for port, name, product, version in service_matches:
                    service_info = {
                        "port": port,
                        "name": name,
                        "product": product,
                        "version": version
                    }
                    self.results["discovered_services"].append(service_info)
                
                # Extract OS detection information
                os_matches = re.findall(r'osclass.*accuracy="([^"]*)".*osfamily="([^"]*)".*osgen="([^"]*)"', xml_content)
                if os_matches:
                    accuracy, os_family, os_gen = os_matches[0]  # Take the most accurate match
                    self.results["os_detection"] = {
                        "accuracy": accuracy,
                        "os_family": os_family,
                        "os_generation": os_gen
                    }
                    self.logger.info(f"OS detected: {os_family} {os_gen} (Accuracy: {accuracy}%)")
                
                # Log discovered services
                if self.results["discovered_services"]:
                    self.logger.info(f"Found {len(self.results['discovered_services'])} services")
                else:
                    self.logger.warning("No services identified")
                    
            except Exception as e:
                self.logger.error(f"Error parsing Nmap service scan output: {str(e)}")
        else:
            self.logger.error("Nmap service scan output file not found")
    
    def _perform_vuln_scan(self):
        """
        Run vulnerability scan using Nmap NSE scripts
        // הפעלת סריקת פגיעויות באמצעות סקריפטי NSE של Nmap
        """
        self.logger.info("Starting vulnerability scan")
        
        if not self.results["discovered_services"]:
            self.logger.warning("No services to scan for vulnerabilities")
            return
            
        # Create output file path
        vuln_scan_output = self.config.get_output_file("nmap_vulns", "xml")
        
        # Get ports with services
        ports_with_services = [service["port"] for service in self.results["discovered_services"]]
        port_str = ",".join(ports_with_services)
        
        # Build script arguments based on discovered services
        scripts = ["vulners", "vuln"]
        
        # Use Nmap for vulnerability scanning
        command = [
            self.config.get_tool_path("nmap"),
            "-sV",                           # Service detection
            "--script=" + ",".join(scripts), # Vulnerability scripts
            "-p", port_str,                  # Scan specific ports
            "-oX", vuln_scan_output,         # XML output
            self.target
        ]
        
        # Run Nmap with extended timeout for vuln scanning
        scan_results = run_tool(command, self.logger, timeout=1800)
        
        if scan_results['returncode'] != 0:
            self.logger.error("Vulnerability scan failed")
            return
            
        # Parse the vulnerability results
        if os.path.exists(vuln_scan_output):
            try:
                with open(vuln_scan_output, 'r') as f:
                    xml_content = f.read()
                
                # Extract vulnerability information (simplified)
                vuln_matches = re.findall(r'id="([^"]*)".*output="([^"]*)"', xml_content)
                
                for vuln_id, output in vuln_matches:
                    if "vulners" in vuln_id or "vuln" in vuln_id:
                        # Check for CVE IDs in output
                        cve_matches = re.findall(r'(CVE-\d+-\d+)', output)
                        for cve in cve_matches:
                            # Try to determine severity (might need enhancement)
                            severity = "Unknown"
                            if "high" in output.lower():
                                severity = "High"
                            elif "medium" in output.lower():
                                severity = "Medium"
                            elif "low" in output.lower():
                                severity = "Low"
                                
                            vuln_info = {
                                "cve": cve,
                                "description": output[:100] + "...",  # Truncate for brevity
                                "severity": severity
                            }
                            self.results["nmap_vulns"].append(vuln_info)
                
                if self.results["nmap_vulns"]:
                    self.logger.info(f"Found {len(self.results['nmap_vulns'])} potential vulnerabilities")
                else:
                    self.logger.info("No vulnerabilities found using Nmap scripts")
                    
            except Exception as e:
                self.logger.error(f"Error parsing Nmap vulnerability scan output: {str(e)}")
        else:
            self.logger.error("Nmap vulnerability scan output file not found")
    
    def _show_results_summary(self):
        """
        Display summary of active scan results
        // הצגת סיכום תוצאות הסריקה האקטיבית
        """
        self.logger.info("Displaying active scan results summary")
        
        # Calculate statistics
        open_ports_count = len(self.results["open_ports"])
        services_count = len(self.results["discovered_services"])
        vulns_count = len(self.results["nmap_vulns"])
        
        self.console.print("")
        self.console.print(Panel(f"[bold cyan]Active Scan Results for [bold yellow]{self.target}[/bold yellow][/bold cyan]", 
                                 expand=False))
        
        # Display open ports
        if open_ports_count > 0:
            self.console.print("[bold blue]Open Ports:[/bold blue]")
            for port in self.results["open_ports"]:
                self.console.print(f"  [cyan]Port {port}[/cyan] - TCP")
        else:
            self.console.print("[yellow]No open ports found[/yellow]")
        
        # Display services
        if services_count > 0:
            self.console.print("\n[bold blue]Discovered Services:[/bold blue]")
            for service in self.results["discovered_services"]:
                port = service["port"]
                name = service["name"] if service["name"] else "unknown"
                product = service["product"] if service["product"] else ""
                version = service["version"] if service["version"] else ""
                
                service_info = f"{product} {version}".strip()
                if service_info:
                    self.console.print(f"  [cyan]Port {port}[/cyan]: {name} ({service_info})")
                else:
                    self.console.print(f"  [cyan]Port {port}[/cyan]: {name}")
        
        # Display OS information
        if self.results["os_detection"] and "os_family" in self.results["os_detection"]:
            os_family = self.results["os_detection"]["os_family"]
            os_gen = self.results["os_detection"].get("os_generation", "")
            accuracy = self.results["os_detection"].get("accuracy", "")
            
            self.console.print("\n[bold blue]Operating System:[/bold blue]")
            os_info = f"{os_family} {os_gen}".strip()
            if accuracy:
                os_info += f" (Accuracy: {accuracy}%)"
            self.console.print(f"  {os_info}")
        
        # Display vulnerabilities
        if vulns_count > 0:
            self.console.print("\n[bold blue]Potential Vulnerabilities:[/bold blue]")
            
            # Group vulnerabilities by severity
            high_vulns = [v for v in self.results["nmap_vulns"] if v["severity"] == "High"]
            medium_vulns = [v for v in self.results["nmap_vulns"] if v["severity"] == "Medium"]
            low_vulns = [v for v in self.results["nmap_vulns"] if v["severity"] == "Low"]
            
            self.console.print(f"  [red]High: {len(high_vulns)}[/red]")
            self.console.print(f"  [yellow]Medium: {len(medium_vulns)}[/yellow]")
            self.console.print(f"  [green]Low: {len(low_vulns)}[/green]")
            
            # Display top 5 critical vulnerabilities
            if high_vulns:
                self.console.print("\n[bold red]Top Critical Vulnerabilities:[/bold red]")
                for vuln in high_vulns[:5]:  # Show top 5
                    self.console.print(f"  [red]{vuln['cve']}[/red]: {vuln['description']}")
        else:
            self.console.print("\n[green]No vulnerabilities detected[/green]")
        
        self.console.print("")  # Extra space 