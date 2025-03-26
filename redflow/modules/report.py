"""
Module for generating reports and result summaries for RedFlow
"""

import os
import json
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.markdown import Markdown

from redflow.utils.logger import get_module_logger


class ReportGenerator:
    """Class for generating reports and summaries"""
    
    def __init__(self, config, logger, console):
        """
        Initialize the reports module
        
        Args:
            config: Configuration object
            logger: Logger instance
            console: Console instance
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("Report", logger)
        self.target = config.target
        self.output_dir = config.output_dir
        self.summaries_dir = config.summaries_dir
    
    def generate(self, results):
        """
        Create a summary report from scan results
        
        Args:
            results: Scan results from all stages
            
        Returns:
            Path to the summary report
        """
        self.logger.info(f"Generating summary report for {self.target}")
        
        # Create visual progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            generate_task = progress.add_task("[cyan]Generating summary report...", total=4)
            
            # Prepare paths and directories
            report_file = os.path.join(self.summaries_dir, f"summary_{self.target.replace('.', '_')}.md")
            json_report_file = os.path.join(self.summaries_dir, f"summary_{self.target.replace('.', '_')}.json")
            progress.update(generate_task, advance=1)
            
            # Create detailed report in Markdown
            self._generate_markdown_report(results, report_file)
            progress.update(generate_task, advance=1)
            
            # Save summary report in JSON
            self._generate_json_report(results, json_report_file)
            progress.update(generate_task, advance=1)
            
            # If required and possible, display the report in the console
            self._display_report_summary(results)
            progress.update(generate_task, advance=1)
        
        self.logger.info(f"Summary report created at {report_file}")
        
        return report_file
    
    def _generate_markdown_report(self, results, report_file):
        """
        Create a Markdown report
        
        Args:
            results: Scan results
            report_file: Path to the report file
        """
        self.logger.debug(f"Creating Markdown report at {report_file}")
        
        # Scan time and date details
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = int(results.get("duration", 0))
        minutes, seconds = divmod(duration, 60)
        
        # Start writing the report
        with open(report_file, "w", encoding="utf-8") as f:
            # Title and summary
            f.write(f"# Scan Report - {self.target}\n\n")
            f.write(f"**Scan Date:** {timestamp}\n")
            f.write(f"**Scan Duration:** {minutes} minutes and {seconds} seconds\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Scan Mode:** {self.config.mode}\n\n")
            
            # Target information
            target_info = results.get("target_info", {})
            f.write("## Target Information\n\n")
            if target_info:
                f.write(f"**Type:** {target_info.get('type', 'Unknown')}\n")
                if target_info.get("type") == "domain":
                    f.write(f"**Domain:** {target_info.get('domain', 'Unknown')}\n")
                    f.write(f"**IP Address:** {target_info.get('ip', 'Unknown')}\n")
                else:
                    f.write(f"**IP Address:** {target_info.get('ip', 'Unknown')}\n")
                    f.write(f"**Hostname:** {target_info.get('hostname', 'Unknown')}\n")
            else:
                f.write("No target information found.\n")
            f.write("\n")
            
            # Open ports
            open_ports = results.get("open_ports", [])
            f.write("\n## Open Ports\n\n")
            f.write("| Port | Service | Version |\n")
            f.write("|------|--------|------|\n")
            for port in open_ports:
                if isinstance(port, str):
                    # If port is a string, just display the port number
                    f.write(f"| {port} | Unknown | Unknown |\n")
                else:
                    # If port is a dictionary, extract data as before
                    port_num = port.get("port", "?")
                    service = port.get("service", "Unknown")
                    version = port.get("version", "")
                    f.write(f"| {port_num} | {service} | {version} |\n")
            f.write("\n")
            
            # Passive reconnaissance
            passive_recon = results.get("passive_recon", {})
            f.write("## Passive Reconnaissance\n\n")
            if passive_recon:
                # WHOIS
                whois_info = passive_recon.get("whois", {})
                if whois_info:
                    f.write("### WHOIS Information\n\n")
                    f.write("| Field | Value |\n")
                    f.write("|------|------|\n")
                    for key, value in whois_info.items():
                        if isinstance(value, str):
                            f.write(f"| {key} | {value} |\n")
                    f.write("\n")
                
                # DNS Records
                dns_records = passive_recon.get("dns_records", [])
                if dns_records:
                    f.write("### DNS Records\n\n")
                    f.write("| Type | Value | TTL |\n")
                    f.write("|------|------|------|\n")
                    for record in dns_records:
                        record_type = record.get("type", "?")
                        record_value = record.get("value", "?")
                        ttl = record.get("ttl", "?")
                        f.write(f"| {record_type} | {record_value} | {ttl} |\n")
                    f.write("\n")
                
                # Subdomains
                subdomains = passive_recon.get("subdomains", [])
                if subdomains:
                    f.write("### Subdomains\n\n")
                    f.write("| Subdomain | IP Address |\n")
                    f.write("|------------|--------|\n")
                    for subdomain in subdomains:
                        if isinstance(subdomain, dict):
                            name = subdomain.get("name", "?")
                            ip = subdomain.get("ip", "לא ידוע")
                            f.write(f"| {name} | {ip} |\n")
                        else:
                            f.write(f"| {subdomain} | לא ידוע |\n")
                    f.write("\n")
                
                # Web Technologies
                web_techs = passive_recon.get("web_technologies", [])
                if web_techs:
                    f.write("### Web Technologies\n\n")
                    f.write("| Technology | Version |\n")
                    f.write("|------------|--------|\n")
                    for tech in web_techs:
                        if isinstance(tech, dict):
                            name = tech.get("name", "?")
                            version = tech.get("version", "לא ידוע")
                            f.write(f"| {name} | {version} |\n")
                        else:
                            f.write(f"| {tech} | לא ידוע |\n")
                    f.write("\n")
            else:
                f.write("No passive reconnaissance performed or no results found.\n\n")
            
            # Enumeration
            enumeration = results.get("enumeration", {})
            f.write("## Enumeration\n\n")
            if enumeration:
                # FTP
                ftp_info = enumeration.get("ftp", {})
                if ftp_info:
                    f.write("### FTP\n\n")
                    f.write(f"**Port:** {ftp_info.get('port', '21')}\n")
                    f.write(f"**Version:** {ftp_info.get('version', 'Unknown')}\n")
                    f.write(f"**Anonymous Access:** {'Yes' if ftp_info.get('anonymous_access', False) else 'No'}\n")
                    
                    directories = ftp_info.get('directories', [])
                    if directories:
                        f.write("\n**Directories Found:**\n\n")
                        for directory in directories:
                            f.write(f"- {directory}\n")
                    f.write("\n")
                
                # SMB
                smb_info = enumeration.get("smb", {})
                if smb_info:
                    f.write("### SMB/Windows\n\n")
                    f.write(f"**Port:** {smb_info.get('port', '445')}\n")
                    f.write(f"**Version:** {smb_info.get('version', 'Unknown')}\n")
                    f.write(f"**Computer Name:** {smb_info.get('computer_name', 'Unknown')}\n")
                    f.write(f"**Domain:** {smb_info.get('domain', 'Unknown')}\n")
                    f.write(f"**Operating System:** {smb_info.get('os', 'Unknown')}\n")
                    
                    shares = smb_info.get('shares', [])
                    if shares:
                        f.write("\n**Shares Found:**\n\n")
                        for share in shares:
                            f.write(f"- {share}\n")
                    
                    users = smb_info.get('users', [])
                    if users:
                        f.write("\n**Users Found:**\n\n")
                        for user in users:
                            f.write(f"- {user}\n")
                    f.write("\n")
                
                # Web
                web_info = enumeration.get("web", [])
                if web_info:
                    f.write("### Web Services\n\n")
                    if isinstance(web_info, list):
                        for web_service in web_info:
                            protocol = web_service.get('protocol', 'http')
                            port = web_service.get('port', '80')
                            f.write(f"**{protocol.upper()} Service on port {port}:**\n\n")
                            
                            directories = web_service.get('directories', [])
                            if directories:
                                f.write("**Directories Found:**\n\n")
                                for directory in directories[:20]:  # Limit to 20 for display
                                    f.write(f"- {directory}\n")
                                if len(directories) > 20:
                                    f.write(f"- ... and {len(directories)-20} more directories\n")
                            
                            files = web_service.get('files', [])
                            if files:
                                f.write("\n**Files Found:**\n\n")
                                for file in files[:20]:  # Limit to 20 for display
                                    f.write(f"- {file}\n")
                                if len(files) > 20:
                                    f.write(f"- ... and {len(files)-20} more files\n")
                            f.write("\n")
                    else:
                        f.write("Web services found but structure is not valid for display.\n\n")
                
                # SSH
                ssh_info = enumeration.get("ssh", {})
                if ssh_info:
                    f.write("### SSH\n\n")
                    f.write(f"**Port:** {ssh_info.get('port', '22')}\n")
                    f.write(f"**Version:** {ssh_info.get('version', 'Unknown')}\n")
                    
                    auth_methods = ssh_info.get('auth_methods', [])
                    if auth_methods:
                        f.write(f"**Authentication Methods:** {', '.join(auth_methods)}\n")
                    
                    f.write(f"**Weak Algorithms:** {'Yes' if ssh_info.get('weak_algorithms', False) else 'No'}\n\n")
                
                # Databases
                db_info = enumeration.get("database", {})
                if db_info:
                    f.write("### Databases\n\n")
                    for db_type, instances in db_info.items():
                        for db in instances:
                            f.write(f"**{db_type} on port {db.get('port', 'Unknown')}:**\n\n")
                            f.write(f"**Version:** {db.get('version', 'Unknown')}\n")
                            f.write(f"**Accessible:** {'Yes' if db.get('accessible', False) else 'No'}\n")
                            f.write(f"**Default Credentials:** {'Yes' if db.get('default_credentials', False) else 'No'}\n\n")
            else:
                f.write("No service enumeration performed or no results found.\n\n")
            
            # Vulnerabilities and Exploitation
            exploitation = results.get("exploitation", {})
            f.write("## Vulnerabilities and Exploitation\n\n")
            if exploitation:
                # Vulnerabilities
                vulnerabilities = exploitation.get("vulnerabilities", [])
                if vulnerabilities:
                    f.write("### Identified Vulnerabilities\n\n")
                    f.write("| Service | Port | Vulnerability | Severity | Description |\n")
                    f.write("|--------|------|---------|-------|--------|\n")
                    for vuln in vulnerabilities:
                        service = vuln.get("service", "Unknown")
                        port = vuln.get("port", "?")
                        name = vuln.get("name", "Unknown")
                        severity = vuln.get("severity", "Unknown")
                        description = vuln.get("description", "").replace("\n", " ")
                        f.write(f"| {service} | {port} | {name} | {severity} | {description} |\n")
                    f.write("\n")
                
                # Credentials
                credentials = exploitation.get("credentials", [])
                if credentials:
                    f.write("### Exposed Credentials\n\n")
                    f.write("| Service | Port | Username | Password |\n")
                    f.write("|--------|------|------------|--------|\n")
                    for cred in credentials:
                        service = cred.get("service", "Unknown")
                        port = cred.get("port", "?")
                        username = cred.get("username", "Unknown")
                        password = cred.get("password", "Unknown")
                        f.write(f"| {service} | {port} | {username} | {password} |\n")
                    f.write("\n")
                
                # Exploits
                exploits = exploitation.get("exploits", [])
                if exploits:
                    f.write("### Potential Exploits\n\n")
                    f.write("| Vulnerability | Name | Path |\n")
                    f.write("|---------|------|--------|\n")
                    for exploit in exploits:
                        vulnerability = exploit.get("vulnerability", "Unknown")
                        name = exploit.get("name", "Unknown")
                        path = exploit.get("path", "Unknown")
                        f.write(f"| {vulnerability} | {name} | {path} |\n")
                    f.write("\n")
            else:
                f.write("No vulnerability analysis performed or no results found.\n\n")
            
            # Conclusions and Recommendations
            f.write("## Conclusions and Recommendations\n\n")
            
            # Generate recommendations based on scan results
            recommendations = self._generate_recommendations(results)
            for category, rec_list in recommendations.items():
                f.write(f"### {category}\n\n")
                for rec in rec_list:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            # End of report
            f.write("---\n\n")
            f.write(f"This report was automatically generated by RedFlow v{self._get_version()}\n")
            f.write(f"Report Generation Date: {timestamp}\n")
    
    def _generate_json_report(self, results, json_report_file):
        """
        Create a JSON report
        
        Args:
            results: Scan results
            json_report_file: Path to the report file
        """
        self.logger.debug(f"Creating JSON report at {json_report_file}")
        
        # Save all results in an organized JSON structure
        summary = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "mode": self.config.mode,
            "duration": results.get("duration", 0),
            "target_info": results.get("target_info", {}),
            "open_ports": results.get("open_ports", []),
            "services": results.get("discovered_services", []),
            "passive_recon": results.get("passive_recon", {}),
            "enumeration": results.get("enumeration", {}),
            "vulnerabilities": results.get("exploitation", {}).get("vulnerabilities", []),
            "credentials": results.get("exploitation", {}).get("credentials", []),
            "exploits": results.get("exploitation", {}).get("exploits", [])
        }
        
        # Add recommendations
        summary["recommendations"] = self._generate_recommendations(results)
        
        # Save to JSON file
        with open(json_report_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)
    
    def _display_report_summary(self, results):
        """
        Display a brief summary of the report in the console
        
        Args:
            results: Scan results
        """
        self.logger.debug("Displaying report summary in console")
        
        self.console.print("\n[bold green]== Findings Summary ==[/bold green]")
        
        # Number of open ports
        open_ports_count = len(results.get("open_ports", []))
        self.console.print(f"[cyan]Open Ports:[/cyan] {open_ports_count}")
        
        # Number of services
        services_count = len(results.get("discovered_services", []))
        self.console.print(f"[cyan]Identified Services:[/cyan] {services_count}")
        
        # Number of vulnerabilities
        if "exploitation" in results:
            vuln_count = len(results["exploitation"].get("vulnerabilities", []))
            self.console.print(f"[cyan]Identified Vulnerabilities:[/cyan] {vuln_count}")
            
            # Vulnerabilities by severity
            if vuln_count > 0:
                severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                for vuln in results["exploitation"].get("vulnerabilities", []):
                    severity = vuln.get("severity", "MEDIUM").upper()
                    if severity in severity_count:
                        severity_count[severity] += 1
                
                self.console.print(f"  [red]Critical:[/red] {severity_count['CRITICAL']}")
                self.console.print(f"  [orange]High:[/orange] {severity_count['HIGH']}")
                self.console.print(f"  [yellow]Medium:[/yellow] {severity_count['MEDIUM']}")
                self.console.print(f"  [green]Low:[/green] {severity_count['LOW']}")
            
            # Exposed credentials
            cred_count = len(results["exploitation"].get("credentials", []))
            if cred_count > 0:
                self.console.print(f"[cyan]Exposed Credentials:[/cyan] {cred_count}")
            
            # Potential exploits
            exploit_count = len(results["exploitation"].get("exploits", []))
            if exploit_count > 0:
                self.console.print(f"[cyan]Potential Exploits:[/cyan] {exploit_count}")
        
        self.console.print("\n[bold blue]Full report saved in the output directory![/bold blue]")
    
    def _generate_recommendations(self, results):
        """
        Generate recommendations based on scan results.
        
        Args:
            results (dict): The complete scan results
            
        Returns:
            dict: Categorized recommendations
        """
        recommendations = {
            "General Security Recommendations": [],
            "Service-Specific Recommendations": [],
            "Vulnerability Mitigation": []
        }
        
        # Add general recommendations
        recommendations["General Security Recommendations"] = [
            "Regularly update and patch all software and services",
            "Implement a robust firewall to restrict access to necessary services only",
            "Enable proper logging and monitoring for all critical services",
            "Configure strong password policies and implement multi-factor authentication where possible"
        ]
        
        # Get service and enumeration data
        services = results.get("services", {}).get("open_ports", [])
        enumeration = results.get("enumeration", {})
        exploitation = results.get("exploitation", {})
        
        # Service-specific recommendations
        if services:
            for port_info in services:
                if isinstance(port_info, dict):
                    port = port_info.get("port", "")
                    service_name = port_info.get("name", "Unknown").lower()
                    
                    # Web server recommendations
                    if service_name in ["http", "https"]:
                        recommendations["Service-Specific Recommendations"].append(
                            f"Consider restricting access to the web server on port {port} if not publicly required"
                        )
                        recommendations["Service-Specific Recommendations"].append(
                            f"Implement HTTPS with strong cipher suites for the web service on port {port}"
                        )
                        
                        # Web directories found
                        web_services = enumeration.get("web", [])
                        for web_service in web_services:
                            if isinstance(web_service, dict) and str(web_service.get("port", "")) == str(port):
                                directories = web_service.get("directories", [])
                                if directories:
                                    recommendations["Service-Specific Recommendations"].append(
                                        f"Review and secure sensitive directories found on the web server (port {port})"
                                    )
                    
                    # FTP recommendations
                    if service_name == "ftp":
                        recommendations["Service-Specific Recommendations"].append(
                            f"Consider replacing FTP on port {port} with SFTP or other encrypted file transfer protocol"
                        )
                        
                        ftp_info = enumeration.get("ftp", {})
                        if ftp_info and ftp_info.get("anonymous_access", False):
                            recommendations["Service-Specific Recommendations"].append(
                                "Disable anonymous FTP access immediately as it poses a significant security risk"
                            )
                    
                    # SSH recommendations
                    if service_name == "ssh":
                        recommendations["Service-Specific Recommendations"].append(
                            f"Configure SSH on port {port} to use only strong ciphers and key exchange algorithms"
                        )
                        recommendations["Service-Specific Recommendations"].append(
                            "Implement key-based authentication for SSH and disable password authentication if possible"
                        )
                        
                        ssh_info = enumeration.get("ssh", {})
                        if ssh_info and ssh_info.get("weak_algorithms", False):
                            recommendations["Service-Specific Recommendations"].append(
                                "Disable weak cryptographic algorithms in the SSH server configuration"
                            )
                    
                    # SMB recommendations
                    if service_name in ["smb", "microsoft-ds"]:
                        recommendations["Service-Specific Recommendations"].append(
                            f"Consider restricting SMB access on port {port} to trusted networks only"
                        )
                        recommendations["Service-Specific Recommendations"].append(
                            "Disable SMBv1 protocol as it has known security vulnerabilities"
                        )
                        
                        smb_info = enumeration.get("smb", {})
                        if smb_info and smb_info.get("shares", []):
                            recommendations["Service-Specific Recommendations"].append(
                                "Review SMB share permissions to ensure principle of least privilege is followed"
                            )
                
                elif isinstance(port_info, str):
                    # If port_info is a string, we don't have detailed service info
                    recommendations["Service-Specific Recommendations"].append(
                        f"Review the necessity of the service running on port {port_info}"
                    )
        
        # Vulnerability-specific recommendations
        vulnerabilities = exploitation.get("vulnerabilities", [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    name = vuln.get("name", "Unknown")
                    severity = vuln.get("severity", "Unknown")
                    
                    if severity.lower() in ["high", "critical"]:
                        recommendations["Vulnerability Mitigation"].append(
                            f"Prioritize patching the {name} vulnerability as it is rated {severity}"
                        )
                    else:
                        recommendations["Vulnerability Mitigation"].append(
                            f"Address the {name} vulnerability according to your security policy"
                        )
        
        # Credentials found
        credentials = exploitation.get("credentials", [])
        if credentials:
            recommendations["Vulnerability Mitigation"].append(
                "Change all exposed credentials immediately and implement a more secure password policy"
            )
        
        return recommendations
    
    def _get_version(self):
        """Returns the tool version"""
        try:
            from redflow import __version__
            return __version__
        except ImportError:
            return "0.1.0" 