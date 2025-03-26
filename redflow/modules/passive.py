"""
Module for performing passive scanning
// מודול לביצוע סריקה פסיבית
"""

import os
import json
import time
import socket
import whois
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from redflow.utils.logger import get_module_logger
from redflow.utils.helpers import run_tool, is_valid_domain, is_valid_ip


class PassiveRecon:
    """Class for performing passive reconnaissance // מחלקה לביצוע איסוף מידע פסיבי"""
    
    def __init__(self, config, logger, console):
        """
        Initialize passive reconnaissance module
        // אתחול מודול הסריקה הפסיבית
        
        Args:
            config: Configuration object
            logger: Logger instance
            console: Console instance
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("PassiveRecon", logger)
        self.target = config.target
        
        # Initialize results dictionary
        self.results = {
            "whois": {},
            "dns": {},
            "subdomains": [],
            "harvester": {},
            "web_technologies": {},
            "waf": {}
        }
    
    def run(self):
        """
        Run all passive scanning tasks
        
        Returns:
            Passive scanning results
        """
        self.logger.info(f"Starting passive scan for {self.target}")
        
        # Create progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            # Run tools based on target type
            if is_valid_domain(self.target):
                self._run_domain_recon(progress)
            else:
                self._run_ip_recon(progress)
            
            # Common tools for all target types
            self._run_common_recon(progress)
        
        # After all scans are done
        self._show_results_summary()
        
        return self.results
    
    def _run_domain_recon(self, progress):
        """
        Run specific tools for domain reconnaissance
        
        Args:
            progress: Progress object
        """
        # WHOIS
        whois_task = progress.add_task("[cyan]Performing WHOIS lookup...", total=1)
        self.results["whois"] = self._perform_whois()
        progress.update(whois_task, completed=1)
        
        # DNS
        dns_task = progress.add_task("[cyan]Performing DNS lookup...", total=1)
        self.results["dns"] = self._perform_dns_lookup()
        progress.update(dns_task, completed=1)
        
        # Subdomain lookup
        subdomain_task = progress.add_task("[cyan]Performing subdomain lookup...", total=1)
        self.results["subdomains"] = self._perform_subdomain_lookup()
        progress.update(subdomain_task, completed=1)
    
    def _run_ip_recon(self, progress):
        """
        Run specific tools for IP reconnaissance
        
        Args:
            progress: Progress object
        """
        # Reverse DNS
        rdns_task = progress.add_task("[cyan]Performing Reverse DNS...", total=1)
        self.results["rdns"] = self._perform_reverse_dns()
        progress.update(rdns_task, completed=1)
    
    def _run_common_recon(self, progress):
        """
        Run common tools for all target types
        
        Args:
            progress: Progress object
        """
        # theHarvester
        harvester_task = progress.add_task("[cyan]Performing information gathering with theHarvester...", total=1)
        if self._is_tool_available("theHarvester"):
            self.results["harvester"] = self._perform_harvester()
        progress.update(harvester_task, completed=1)
        
        # WhatWeb
        webtech_task = progress.add_task("[cyan]Identifying website technologies with WhatWeb...", total=1)
        if self._is_tool_available("whatweb"):
            self.results["web_technologies"] = self._perform_whatweb()
        progress.update(webtech_task, completed=1)
        
        # WAF
        waf_task = progress.add_task("[cyan]Identifying web application firewall (WAF)...", total=1)
        if self._is_tool_available("wafw00f"):
            self.results["waf"] = self._perform_wafw00f()
        progress.update(waf_task, completed=1)
    
    def _perform_whois(self):
        """
        Perform WHOIS lookup
        
        Returns:
            Dictionary with WHOIS results
        """
        self.logger.info(f"Performing WHOIS lookup for {self.target}")
        
        try:
            # Try using python-whois library
            w = whois.whois(self.target)
            result = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "raw": w.text
            }
            
            # Save to file
            output_file = self.config.get_output_file("whois", "txt")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(w.text)
            
            self.logger.debug(f"WHOIS data saved to: {output_file}")
            return result
        
        except Exception as e:
            self.logger.error(f"Error performing WHOIS: {str(e)}")
            
            # Try using whois tool if the library failed
            output_file = self.config.get_output_file("whois", "txt")
            cmd = ["whois", self.target]
            result = run_tool(cmd, output_file=output_file)
            
            if result["returncode"] == 0:
                self.logger.debug(f"WHOIS data saved to: {output_file}")
                return {"raw": result["stdout"]}
            
            self.logger.error(f"Error performing whois tool: {result.get('error', 'Unknown error')}")
            return {"error": str(e)}
    
    def _perform_dns_lookup(self):
        """
        Perform DNS queries
        
        Returns:
            List of DNS records
        """
        self.logger.info(f"Performing DNS lookup for {self.target}")
        
        # DNS record types for testing
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        results = []
        
        output_file = self.config.get_output_file("dns", "txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"DNS Lookup for {self.target}\n")
            f.write("=" * 50 + "\n\n")
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    f.write(f"{record_type} Records:\n")
                    
                    for answer in answers:
                        record_data = str(answer)
                        f.write(f"  {record_data}\n")
                        results.append({
                            "type": record_type,
                            "data": record_data
                        })
                
                except dns.resolver.NoAnswer:
                    f.write(f"{record_type} Records: None\n")
                
                except dns.resolver.NXDOMAIN:
                    f.write(f"Error: Domain {self.target} does not exist\n")
                    break
                
                except Exception as e:
                    error_msg = f"Error querying {record_type} records: {str(e)}"
                    f.write(f"{error_msg}\n")
                    self.logger.error(error_msg)
                
                f.write("\n")
        
        self.logger.debug(f"DNS data saved to: {output_file}")
        return results
    
    def _perform_reverse_dns(self):
        """
        Perform Reverse DNS lookup for an IP address
        
        Returns:
            Reverse DNS results
        """
        self.logger.info(f"Performing Reverse DNS for {self.target}")
        
        result = {"hostnames": []}
        
        try:
            hostname, _, _ = socket.gethostbyaddr(self.target)
            result["primary_hostname"] = hostname
            result["hostnames"].append(hostname)
            
            # Save to file
            output_file = self.config.get_output_file("reverse_dns", "txt")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Reverse DNS for {self.target}:\n")
                f.write(f"Hostname: {hostname}\n")
            
            self.logger.debug(f"Reverse DNS data saved to: {output_file}")
        
        except (socket.herror, socket.gaierror) as e:
            self.logger.warning(f"Reverse DNS not found for {self.target}: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    def _perform_subdomain_lookup(self):
        """
        Perform subdomain lookup
        
        Returns:
            List of found subdomains
        """
        self.logger.info(f"Performing subdomain lookup for {self.target}")
        
        # Check if sublist3r is available
        if not self._is_tool_available("sublist3r"):
            self.logger.warning("sublist3r tool not found, skipping subdomain lookup")
            return {"error": "sublist3r tool not found"}
        
        output_file = self.config.get_output_file("sublist3r", "txt")
        cmd = ["sublist3r", "-d", self.target, "-o", output_file]
        
        result = run_tool(cmd, timeout=600)  # Longer timeout as it might take time
        
        if result["returncode"] == 0:
            self.logger.debug(f"sublist3r results saved to: {output_file}")
            
            # Analyze results
            subdomains = []
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            subdomains.append(line)
            
            return subdomains
        
        # If subdomain lookup fails, try using DNS to find common subdomains
        self.logger.warning(f"subdomain lookup with sublist3r failed: {result.get('error', '')}")
        
        # List of common subdomains for local testing
        common_subdomains = ["www", "mail", "ftp", "webmail", "admin", "test", "dev", "staging"]
        found_subdomains = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except socket.gaierror:
                pass
        
        return found_subdomains
    
    def _perform_harvester(self):
        """
        Perform information gathering with theHarvester
        
        Returns:
            theHarvester results
        """
        self.logger.info(f"Performing information gathering with theHarvester for {self.target}")
        
        # Common sources for theHarvester
        sources = "bing,google,linkedin,twitter,yahoo"
        
        output_file = self.config.get_output_file("harvester", "txt")
        cmd = ["theHarvester", "-d", self.target, "-b", sources, "-f", output_file]
        
        result = run_tool(cmd, timeout=300)
        
        if result["returncode"] == 0:
            self.logger.debug(f"theHarvester results saved to: {output_file}")
            
            harvester_results = {
                "emails": [],
                "hosts": [],
                "raw": result["stdout"]
            }
            
            # Analyze results
            for line in result["stdout"].splitlines():
                line = line.strip()
                if "@" in line and not line.startswith("["):
                    harvester_results["emails"].append(line)
                elif self.target in line and "." in line and not line.startswith("["):
                    harvester_results["hosts"].append(line)
            
            return harvester_results
        
        self.logger.warning(f"theHarvester failed: {result.get('error', '')}")
        return {"error": result.get("error", "Unknown error")}
    
    def _perform_whatweb(self):
        """
        Identify website technologies with WhatWeb
        
        Returns:
            WhatWeb results
        """
        self.logger.info(f"Identifying website technologies for {self.target}")
        
        output_file = self.config.get_output_file("whatweb", "txt")
        target_url = self.target
        
        # Add HTTP if needed
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"
        
        cmd = ["whatweb", "--log-json", output_file, target_url]
        
        result = run_tool(cmd)
        
        if result["returncode"] == 0:
            self.logger.debug(f"WhatWeb results saved to: {output_file}")
            
            # Try to read JSON file
            webtech_results = {"technologies": []}
            if os.path.exists(output_file):
                try:
                    with open(output_file, "r", encoding="utf-8") as f:
                        whatweb_json = json.load(f)
                        
                        if isinstance(whatweb_json, list) and whatweb_json:
                            tech_item = whatweb_json[0]
                            
                            if "plugins" in tech_item:
                                for tech, details in tech_item["plugins"].items():
                                    webtech_results["technologies"].append({
                                        "name": tech,
                                        "version": details.get("version", [""])[0] if isinstance(details.get("version", []), list) else ""
                                    })
                except json.JSONDecodeError:
                    self.logger.warning(f"Unable to analyze WhatWeb JSON output")
            
            return webtech_results
        
        self.logger.warning(f"WhatWeb failed: {result.get('error', '')}")
        return {"error": result.get("error", "Unknown error")}
    
    def _perform_wafw00f(self):
        """
        Identify web application firewall (WAF) with wafw00f
        
        Returns:
            wafw00f results
        """
        self.logger.info(f"Identifying web application firewall (WAF) for {self.target}")
        
        output_file = self.config.get_output_file("wafw00f", "txt")
        target_url = self.target
        
        # Add HTTP if needed
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"
        
        cmd = ["wafw00f", target_url]
        
        result = run_tool(cmd, output_file=output_file)
        
        if result["returncode"] == 0:
            self.logger.debug(f"wafw00f results saved to: {output_file}")
            
            # Analyze results
            waf_results = {"detected": False, "waf_name": "None"}
            
            for line in result["stdout"].splitlines():
                if "is behind" in line.lower() or "protected by" in line.lower():
                    waf_results["detected"] = True
                    parts = line.split("WAF")
                    if len(parts) > 1:
                        waf_name = parts[1].strip()
                        waf_results["waf_name"] = waf_name
            
            return waf_results
        
        self.logger.warning(f"wafw00f failed: {result.get('error', '')}")
        return {"error": result.get("error", "Unknown error")}
    
    def _is_tool_available(self, tool_name):
        """
        Check if a tool is available
        
        Args:
            tool_name: Tool name
            
        Returns:
            Boolean: Whether the tool is available
        """
        tool_path = self.config.get_tool_path(tool_name)
        
        # In development environment, return True for testing
        if os.name == "nt":
            return True
            
        return os.path.exists(tool_path) and os.access(tool_path, os.X_OK)
    
    def _show_results_summary(self):
        """Display passive scanning results summary"""
        self.console.print("\n[bold green]Passive Scan Summary:[/bold green]")
        
        # WHOIS
        if "whois" in self.results and self.results["whois"] and not "error" in self.results["whois"]:
            whois_data = self.results["whois"]
            registrar = whois_data.get("registrar", "Unknown")
            creation = whois_data.get("creation_date", "Unknown")
            self.console.print(f"[cyan]WHOIS:[/cyan] Registrar: {registrar}, Creation Date: {creation}")
        
        # DNS
        if "dns" in self.results and self.results["dns"]:
            self.console.print(f"[cyan]DNS:[/cyan] Found {len(self.results['dns'])} records")
        
        # Subdomains
        if "subdomains" in self.results and isinstance(self.results["subdomains"], list):
            subdomains = self.results["subdomains"]
            self.console.print(f"[cyan]Subdomains:[/cyan] Found {len(subdomains)} subdomains")
        
        # WhatWeb
        if "web_technologies" in self.results and "technologies" in self.results["web_technologies"]:
            tech_count = len(self.results["web_technologies"]["technologies"])
            self.console.print(f"[cyan]Website Technologies:[/cyan] Identified {tech_count} technologies")
        
        # WAF
        if "waf" in self.results and "detected" in self.results["waf"]:
            if self.results["waf"]["detected"]:
                self.console.print(f"[cyan]Web Application Firewall:[/cyan] Detected WAF of type {self.results['waf']['waf_name']}")
            else:
                self.console.print("[cyan]Web Application Firewall:[/cyan] No web application firewall (WAF) detected")
        
        self.console.print("")  # Additional space 