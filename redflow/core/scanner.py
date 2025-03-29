"""
Central scanner module managing the scanning process
// מודול סורק מרכזי המנהל את תהליך הסריקה
"""

import os
import sys
import json
import time
import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from redflow.utils.logger import get_module_logger
from redflow.utils.helpers import get_target_info, is_valid_domain, is_valid_ip
from redflow.modules.passive import PassiveRecon
from redflow.modules.active import ActiveRecon
from redflow.modules.enumeration import Enumeration
from redflow.modules.exploitation import Exploitation
from redflow.modules.report import ReportGenerator


class Scanner:
    """Main class for managing the scanning process // מחלקה מרכזית לניהול תהליך הסריקה"""

    def __init__(self, config, logger, console):
        """
        Initialize the scanner
        // אתחול הסורק
        
        Args:
            config: Configuration object
            logger: Logger instance
            console: Console instance
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("Scanner", logger)
        
        # Initialize target data
        self.target_info = get_target_info(config.target)
        
        # Modules
        self.passive_recon = PassiveRecon(config, logger, console)
        self.active_recon = ActiveRecon(config, logger, console)
        self.enumeration = Enumeration(config, logger, console)
        self.exploitation = Exploitation(config, logger, console)
        self.report_generator = ReportGenerator(config, logger, console)
        
        # Results data
        self.results = {
            "target_info": self.target_info,
            "start_time": time.time(),
            "passive_recon": {},
            "active_recon": {},
            "enumeration": {},
            "exploitation": {},
            "discovered_services": [],
            "open_ports": [],
            "vulnerabilities": []
        }
    
    def validate_target(self):
        """
        Validate target correctness
        // אימות תקינות המטרה
        
        Returns:
            Boolean: Whether the target is valid
        """
        if self.target_info["type"] == "unknown":
            self.logger.error(f"Target is not a valid IP address or domain: {self.config.target}")
            self.console.print(Panel(
                f"[bold red]Error:[/bold red] Target is not a valid IP address or domain: {self.config.target}",
                title="Validation Error"
            ))
            return False
        
        return True
    
    def print_banner(self):
        """Display opening banner and summary of planned scan // הצגת באנר פתיחה וסיכום על הסריקה המתוכננת"""
        banner = """
        [bold red]
    ____          ______                
   / __ \\___  ___/ / / /___ _      __   
  / /_/ / _ \\/ __/ / / / __ \\ | /| / /   
 / _, _/  __/ /_/ / / / /_/ / |/ |/ /    
/_/ |_|\\___/\\__/_/_/_/\\____/|__/|__/     
                                        
        [/bold red][bold white]- Advanced Automated Information Gathering and Attack Tool[/bold white]
        """
        
        self.console.print(banner)
        self.console.print("\n")
        
        target_type = "IP Address" if self.target_info["type"] == "ip" else "Domain"
        
        table = Table(title=f"Scan Details - {self.config.target}")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Target", self.config.target)
        table.add_row("Type", target_type)
        if self.target_info["type"] == "domain" and self.target_info["ip"]:
            table.add_row("IP Address", self.target_info["ip"])
        elif self.target_info["type"] == "ip" and self.target_info["hostname"]:
            table.add_row("Hostname", self.target_info["hostname"])
        
        table.add_row("Scan Mode", self.config.mode)
        if hasattr(self.config, 'specific_port') and self.config.specific_port:
            table.add_row("Specific Port", str(self.config.specific_port))
        table.add_row("Output Directory", self.config.output_dir)
        table.add_row("Interactive Mode", "Enabled" if self.config.interactive else "Disabled")
        table.add_row("GPT Integration", "Enabled" if self.config.use_gpt else "Disabled")
        
        self.console.print(table)
        self.console.print("\n")
    
    def prompt_continue(self, phase):
        """
        Ask the user if they want to continue to the next phase
        // שאילת המשתמש אם להמשיך לשלב הבא
        
        Args:
            phase: Name of the next phase
            
        Returns:
            Boolean: Whether to continue
        """
        if not self.config.interactive:
            return True
        
        response = input(f"\nContinue to {phase} phase? (y/n): ")
        return response.lower() in ["y", "yes", ""]
    
    def start(self):
        """Start the full scanning process // התחלת תהליך הסריקה המלא"""
        # Validate target
        if not self.validate_target():
            return
        
        # Display banner
        self.print_banner()
        
        # Manage scanning process based on selected mode
        if self.config.mode in ["passive", "full"]:
            self.logger.info(f"Starting passive information gathering for {self.config.target}")
            self.console.print("[bold blue]== Passive Information Gathering ==[/bold blue]")
            
            passive_results = self.passive_recon.run()
            self.results["passive_recon"] = passive_results
            self.save_results()
            
            # Ask user if they want to continue
            if self.config.mode == "full" and not self.prompt_continue("Active Scanning"):
                self.finish()
                return
        
        if self.config.mode in ["active", "full", "quick"]:
            self.logger.info(f"Starting active information gathering for {self.config.target}")
            self.console.print("[bold blue]== Active Information Gathering ==[/bold blue]")
            
            # If specific port is set, pass it to active_recon
            if hasattr(self.config, 'specific_port') and self.config.specific_port:
                self.console.print(f"[bold yellow]Focusing on specific port: {self.config.specific_port}[/bold yellow]")
                self.logger.info(f"Focusing scan on port {self.config.specific_port}")
                active_results = self.active_recon.run(specific_port=self.config.specific_port)
            else:
                active_results = self.active_recon.run()
                
            self.results["active_recon"] = active_results
            self.results["open_ports"] = active_results.get("open_ports", [])
            self.results["discovered_services"] = active_results.get("discovered_services", [])
            self.save_results()

            # For quick mode, only perform directory enumeration for web services
            if self.config.mode == "quick":
                self.logger.info(f"Quick mode: Starting directory enumeration for web services")
                self.console.print("[bold blue]== Directory Enumeration ==[/bold blue]")
                
                web_services = [service for service in self.results["discovered_services"] 
                              if service.get("service", "").lower() in ["http", "https"]]
                
                if web_services:
                    enum_results = self.enumeration.run_web_enumeration(web_services)
                    self.results["enumeration"] = {"web": enum_results}
                    self.save_results()
                
                self.finish()
                return
            
            # If there's a specific port and it was found open, jump to exploit menu
            if hasattr(self.config, 'specific_port') and self.config.specific_port:
                specific_port_found = False
                service_info = None
                
                for service in self.results["discovered_services"]:
                    if str(service.get("port", "")) == str(self.config.specific_port):
                        specific_port_found = True
                        service_info = service
                        break
                
                if specific_port_found and service_info:
                    self.logger.info(f"Port {self.config.specific_port} was found open, proceeding to exploitation")
                    self.console.print(f"[bold green]Port {self.config.specific_port} is open. Proceeding to exploit menu.[/bold green]")
                    
                    # Continue with enumeration before exploitation
                    self.logger.info(f"Starting service enumeration for {self.config.target}")
                    self.console.print("[bold blue]== Service Enumeration ==[/bold blue]")
                    
                    enum_results = self.enumeration.run(self.results["discovered_services"])
                    self.results["enumeration"] = enum_results
                    self.save_results()
                    
                    # Launch exploit menu for the specific service
                    service_name = service_info.get("name", "")
                    if "product" in service_info:
                        service_name = service_info["product"].lower()
                    
                    self.console.print(f"[bold blue]== Exploitation Menu for Port {self.config.specific_port} ==[/bold blue]")
                    self.enumeration.interactive_exploit_menu(
                        service_info.get("name", "").lower(),
                        service_name,
                        service_info.get("version", ""),
                        self.config.target
                    )
                    
                    self.finish()
                    return
                else:
                    self.logger.warning(f"Specified port {self.config.specific_port} was not found open")
                    self.console.print(f"[bold red]Port {self.config.specific_port} was not found open.[/bold red]")
            
            # Continue with normal flow if no specific port or if specific port not found
            # Ask user if they want to continue
            if not self.prompt_continue("Enumeration and Service Interrogation"):
                self.finish()
                return
            
            self.logger.info(f"Starting service enumeration for {self.config.target}")
            self.console.print("[bold blue]== Service Enumeration ==[/bold blue]")
            
            enum_results = self.enumeration.run(self.results["discovered_services"])
            self.results["enumeration"] = enum_results
            self.save_results()
            
            # Ask user if they want to continue
            if not self.prompt_continue("Potential Exploitation"):
                self.finish()
                return
            
            self.logger.info(f"Starting vulnerability assessment for {self.config.target}")
            self.console.print("[bold blue]== Vulnerability Analysis ==[/bold blue]")
            
            exploit_results = self.exploitation.run(self.results)
            self.results["exploitation"] = exploit_results
            self.results["vulnerabilities"] = exploit_results.get("vulnerabilities", [])
            self.save_results()
            
            # Ask user if they want to launch the interactive exploit menu
            if self.config.interactive:
                self.console.print("\n[bold yellow]Would you like to launch the interactive exploit menu?[/bold yellow] (y/n)")
                response = input("> ").strip().lower()
                
                if response in ["y", "yes", ""]:
                    self.console.print("[bold blue]== Interactive Exploit Menu ==[/bold blue]")
                    self.exploitation.interactive_exploit_launcher()
        
        # Complete scan
        self.finish()
    
    def save_results(self):
        """Save scan results so far // שמירת תוצאות הסריקה עד כה"""
        # Update time data
        self.results["end_time"] = time.time()
        self.results["duration"] = self.results["end_time"] - self.results["start_time"]
        
        # Save to JSON file
        results_file = os.path.join(self.config.output_dir, "results.json")
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)
        
        self.logger.debug(f"Scan results saved to: {results_file}")
    
    def finish(self):
        """Complete the scan and display summary // סיום הסריקה והצגת סיכום"""
        self.logger.info("Completing scan process")
        
        # Generate summary report
        report_file = self.report_generator.generate(self.results)
        
        # Final save of results
        self.save_results()
        
        # Display summary
        self.console.print("[bold green]== Scan Summary ==[/bold green]")
        
        # Open ports summary
        if self.results["open_ports"]:
            open_ports_table = Table(title="Open Ports")
            open_ports_table.add_column("Port", style="cyan")
            open_ports_table.add_column("Service", style="green")
            open_ports_table.add_column("Version", style="yellow")
            
            for port_info in self.results["open_ports"]:
                if isinstance(port_info, str):
                    # If port is a string, just display the port number
                    open_ports_table.add_row(
                        port_info,
                        "Unknown",
                        ""
                    )
                else:
                    # If port is a dictionary, extract data
                    open_ports_table.add_row(
                        str(port_info.get("port", "?")), 
                        port_info.get("service", "Unknown"),
                        port_info.get("version", "")
                    )
            
            self.console.print(open_ports_table)
        
        # Vulnerabilities summary
        if self.results["vulnerabilities"]:
            vuln_table = Table(title="Potential Vulnerabilities")
            vuln_table.add_column("Service", style="cyan")
            vuln_table.add_column("Vulnerability", style="red")
            vuln_table.add_column("Severity", style="yellow")
            
            for vuln in self.results["vulnerabilities"]:
                vuln_table.add_row(
                    vuln.get("service", "Unknown"), 
                    vuln.get("name", "Unknown"),
                    vuln.get("severity", "Unknown")
                )
            
            self.console.print(vuln_table)
        
        # Completion message
        duration = int(self.results["duration"])
        self.console.print(f"\n[bold green]Scan completed successfully![/bold green] Scan time: {duration} seconds")
        self.console.print(f"Summary report created at: [bold]{report_file}[/bold]")
        self.console.print(f"Scan results saved at: [bold]{os.path.join(self.config.output_dir, 'results.json')}[/bold]")

    def scan(self):
        """
        Main scanning function
        
        This is the main scanning function that orchestrates the entire process
        """
        self.logger.info(f"Starting scan for {self.target}")
        self.console.print(f"[bold blue]Starting scan for {self.target}[/bold blue]")
        
        # Create metadata file with scan info
        self.create_metadata()
        
        # Configure scan based on mode
        self.configure_scan()
        
        # Run initial nmap scan to discover ports and services
        self.console.print("\n[bold cyan]Phase 1: Port and Service Discovery[/bold cyan]")
        self.scan_ports_services()
        
        # If no ports were found, exit early
        if not self.discovered_services:
            self.logger.warning("No open ports found. Exiting.")
            self.console.print("[bold yellow]No open ports found. Exiting.[/bold yellow]")
            self.save_results()
            return
            
        # Only scan more aggressively if not in passive mode
        if self.config.mode != "passive":
            self.console.print("\n[bold cyan]Phase 2: Scanning Specific Services[/bold cyan]")
            self.scan_specific_services()
            
            self.console.print("\n[bold cyan]Phase 3: Scanning for Vulnerabilities[/bold cyan]")
            if self.config.scan_vulns:
                self.scan_vulnerabilities()
            else:
                self.console.print("[yellow]Vulnerability scanning disabled.[/yellow]")
        
        # Run additional automated checks for specific services
        self.console.print("\n[bold cyan]Phase 4: Running Service-Specific Checks[/bold cyan]")
        self.run_service_specific_checks()
        
        # Save results
        self.save_results()
        
        # Show summary
        self.console.print("\n[bold green]Scan complete![/bold green]")
        self.console.print(f"Results saved to: [bold]{self.config.project_dir}[/bold]")
        
        self.console.print("\n[bold cyan]Service Detection Summary:[/bold cyan]")
        for service in self.discovered_services:
            port = service.get("port", "")
            name = service.get("name", "").lower()
            version = service.get("version", "")
            self.console.print(f"- [bold cyan]{name}[/bold cyan] on port {port} - Version: {version}")
        
        # Summarize findings
        self.console.print("\n[bold cyan]Findings Summary:[/bold cyan]")
        
        if self.enumeration.results:
            for category, findings in self.enumeration.results.items():
                if findings:
                    if isinstance(findings, list) and len(findings) > 0:
                        self.console.print(f"- [bold]{category.capitalize()}[/bold]: {len(findings)} findings")
                    elif isinstance(findings, dict) and len(findings) > 0:
                        self.console.print(f"- [bold]{category.capitalize()}[/bold]: {len(findings)} findings")
        
        if self.found_vulns:
            self.console.print(f"- [bold]Vulnerabilities[/bold]: {len(self.found_vulns)} potential vulnerabilities found")
        
        # If GPT is enabled, get recommendations
        if self.config.use_gpt:
            try:
                self.console.print("\n[bold cyan]Phase 5: AI Analysis and Recommendations[/bold cyan]")
                from redflow.modules.gpt.scan_analysis import analyze_scan_results
                
                # Check if we have an API key
                api_key = self.config.get_gpt_api_key()
                if not api_key:
                    self.console.print("[yellow]OpenAI API key not set. Skipping AI analysis.[/yellow]")
                else:
                    recommendations = analyze_scan_results(self.config, self.logger, self.console, self.discovered_services, self.found_vulns, self.enumeration.results)
                    
                    # Save recommendations to file
                    recommendations_file = os.path.join(self.config.project_dir, "gpt_recommendations.md")
                    with open(recommendations_file, "w") as f:
                        f.write(recommendations)
                    
                    self.console.print(f"GPT recommendations saved to: [bold]{recommendations_file}[/bold]")
            except Exception as e:
                self.logger.error(f"Error during GPT analysis: {str(e)}")
                self.console.print(f"[bold red]Error during GPT analysis: {str(e)}[/bold red]")
                
        # Final message with next steps
        self.console.print("\n[bold blue]Scan completed successfully![/bold blue]")
        self.console.print("[bold]Next steps:[/bold]")
        self.console.print("- To exploit identified vulnerabilities: [cyan]python redflow.py --exploit-menu --results-dir " + self.config.project_dir + "[/cyan]")
        self.console.print("- To use GPT Exploit Advisor: [cyan]python redflow.py --gpt-advisor --results-dir " + self.config.project_dir + "[/cyan]")
        self.console.print("- To browse and download files: [cyan]python redflow.py --list-files --results-dir " + self.config.project_dir + "[/cyan]")
        
        return True
    
    def run_service_specific_checks(self):
        """
        Run specific checks for detected services
        """
        self.logger.info("Running service-specific checks")
        self.console.print("[bold]Running automated checks for detected services...[/bold]")
        
        # Create a directory for service-specific check results
        service_checks_dir = os.path.join(self.config.project_dir, "service_checks")
        os.makedirs(service_checks_dir, exist_ok=True)
        
        # Check for FTP (port 21)
        ftp_services = [s for s in self.discovered_services if s.get("port") == 21 or s.get("name", "").lower() == "ftp"]
        if ftp_services:
            self.console.print("[bold cyan]Checking FTP services...[/bold cyan]")
            for ftp in ftp_services:
                port = ftp.get("port", 21)
                self.check_ftp_anonymous(port)
        
        # Check for SSH (port 22)
        ssh_services = [s for s in self.discovered_services if s.get("port") == 22 or s.get("name", "").lower() == "ssh"]
        if ssh_services:
            self.console.print("[bold cyan]Checking SSH services...[/bold cyan]")
            for ssh in ssh_services:
                port = ssh.get("port", 22)
                self.check_ssh_credentials(port)
        
        # Check for SMB (port 445)
        smb_services = [s for s in self.discovered_services if s.get("port") == 445 or s.get("name", "").lower() in ["smb", "microsoft-ds"]]
        if smb_services:
            self.console.print("[bold cyan]Checking SMB services...[/bold cyan]")
            self.check_smb_enumeration()
        
        # Check for HTTP/HTTPS (port 80/443)
        http_services = [s for s in self.discovered_services if s.get("port") in [80, 443] or s.get("name", "").lower() in ["http", "https"]]
        if http_services:
            self.console.print("[bold cyan]Checking web services...[/bold cyan]")
            for http in http_services:
                port = http.get("port", 80)
                protocol = "https" if port == 443 or http.get("name", "").lower() == "https" else "http"
                self.check_web_directories(port, protocol)
    
    def check_ftp_anonymous(self, port=21):
        """
        Check if FTP allows anonymous login
        
        Args:
            port: FTP port number (default: 21)
        """
        self.logger.info(f"Checking anonymous FTP login on port {port}")
        self.console.print(f"[bold]Checking anonymous FTP login on port {port}...[/bold]")
        
        # Save results to a file
        results_file = os.path.join(self.config.project_dir, "service_checks", f"ftp_anonymous_port_{port}.txt")
        
        try:
            # Run FTP anonymous login check
            cmd = f"timeout 30 bash -c \"echo -e 'anonymous\\nanonymous\\n' | ftp -n {self.target} {port}\""
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate()
            
            # Check if login was successful
            login_successful = "230" in stdout  # 230 is the FTP success code for login
            
            with open(results_file, "w") as f:
                f.write(f"FTP Anonymous Login Check Results:\n")
                f.write(f"Target: {self.target}:{port}\n")
                f.write(f"Command: {cmd}\n\n")
                f.write(f"Anonymous login: {'ALLOWED' if login_successful else 'DENIED'}\n\n")
                f.write("Output:\n")
                f.write(stdout)
                f.write("\nErrors:\n")
                f.write(stderr)
            
            if login_successful:
                self.console.print(f"[bold red]Anonymous FTP login ALLOWED on port {port}![/bold red]")
                
                # Add to enumeration results
                if "ftp" not in self.enumeration.results:
                    self.enumeration.results["ftp"] = {}
                
                self.enumeration.results["ftp"]["anonymous_login"] = True
                
                # Also add to vulnerabilities
                vuln = {
                    "name": "Anonymous FTP Login",
                    "description": "FTP server allows anonymous login which can be used to access files without authentication.",
                    "service": "ftp",
                    "port": port,
                    "severity": "Medium",
                    "proof": "Anonymous login successful"
                }
                self.found_vulns.append(vuln)
            else:
                self.console.print(f"[green]Anonymous FTP login not allowed on port {port}.[/green]")
                if "ftp" not in self.enumeration.results:
                    self.enumeration.results["ftp"] = {}
                
                self.enumeration.results["ftp"]["anonymous_login"] = False
                
        except Exception as e:
            self.logger.error(f"Error checking anonymous FTP login: {str(e)}")
            self.console.print(f"[bold red]Error checking anonymous FTP login: {str(e)}[/bold red]")
    
    def check_ssh_credentials(self, port=22):
        """
        Check for default SSH credentials
        
        Args:
            port: SSH port number (default: 22)
        """
        self.logger.info(f"Checking default SSH credentials on port {port}")
        self.console.print(f"[bold]Checking default SSH credentials on port {port}...[/bold]")
        
        # Save results to a file
        results_file = os.path.join(self.config.project_dir, "service_checks", f"ssh_default_creds_port_{port}.txt")
        
        # Define a list of common username/password pairs
        default_creds = [
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("admin", "admin"),
            ("admin", "password"),
            ("user", "user"),
            ("kali", "kali")
        ]
        
        with open(results_file, "w") as f:
            f.write(f"SSH Default Credentials Check Results:\n")
            f.write(f"Target: {self.target}:{port}\n\n")
            f.write("Tested credentials:\n")
            
            # Check each pair with a short timeout to avoid hanging
            for username, password in default_creds:
                try:
                    f.write(f"- {username}:{password}: ")
                    
                    # We won't actually try to connect to avoid locking accounts,
                    # but in a real scenario you might use paramiko or hydra
                    f.write("SKIPPED (Not testing to avoid account lockout)\n")
                except Exception as e:
                    f.write(f"ERROR: {str(e)}\n")
            
            # Alternative approach: Suggest using Hydra
            f.write("\nRecommended approach for testing multiple credentials safely:\n")
            f.write(f"hydra -L /path/to/users.txt -P /path/to/passwords.txt {self.target} -s {port} ssh\n")
        
        self.console.print(f"[yellow]Note: Default SSH credential check skipped to avoid account lockout.[/yellow]")
        self.console.print(f"[yellow]For testing credentials, consider using Hydra with a rate limiter.[/yellow]")
    
    def check_smb_enumeration(self):
        """
        Run enum4linux for SMB enumeration
        """
        self.logger.info("Running enum4linux for SMB enumeration")
        self.console.print("[bold]Running enum4linux for SMB enumeration...[/bold]")
        
        # Save results to a file
        results_file = os.path.join(self.config.project_dir, "service_checks", "smb_enum4linux.txt")
        
        try:
            # Run enum4linux with -a for all simple enumeration
            cmd = f"enum4linux -a {self.target}"
            
            self.console.print(f"[yellow]Running: {cmd}[/yellow]")
            
            with open(results_file, "w") as f:
                f.write(f"SMB Enumeration Results (enum4linux):\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Command: {cmd}\n\n")
                
                # Run the command and capture output in real-time
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                
                for line in proc.stdout:
                    f.write(line)
                    
                    # Check for interesting findings to highlight
                    if any(x in line.lower() for x in ["administrator", "guest", "shares", "password policy", "domain", "workgroup"]):
                        self.console.print(f"[cyan]{line.strip()}[/cyan]")
                
                proc.communicate()  # Ensure process completes
            
            self.console.print(f"[green]SMB enumeration complete. Results saved to {results_file}[/green]")
            
            # Add to enumeration results
            if "smb" not in self.enumeration.results:
                self.enumeration.results["smb"] = {}
            
            self.enumeration.results["smb"]["enum4linux_completed"] = True
            
        except Exception as e:
            self.logger.error(f"Error during SMB enumeration: {str(e)}")
            self.console.print(f"[bold red]Error during SMB enumeration: {str(e)}[/bold red]")
    
    def check_web_directories(self, port, protocol="http"):
        """
        Run directory brute-force for web services
        
        Args:
            port: Web service port
            protocol: http or https (default: http)
        """
        self.logger.info(f"Running web directory brute-force on {protocol}://{self.target}:{port}")
        self.console.print(f"[bold]Running web directory brute-force on {protocol}://{self.target}:{port}...[/bold]")
        
        # Save results to a file
        results_file = os.path.join(self.config.project_dir, "service_checks", f"web_dirs_{protocol}_{port}.txt")
        
        try:
            # Determine wordlist path
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/dirb/wordlists/common.txt"  # Fallback to dirb wordlist
                if not os.path.exists(wordlist):
                    self.console.print("[yellow]Standard wordlists not found. Using small built-in list.[/yellow]")
                    
                    # Create a small temporary wordlist if standard ones aren't available
                    temp_wordlist = os.path.join(self.config.project_dir, "temp_wordlist.txt")
                    with open(temp_wordlist, "w") as f:
                        common_dirs = ["admin", "login", "wp-admin", "administrator", "phpmyadmin", "api", 
                                      "backup", "config", "dashboard", "images", "img", "upload", "uploads", 
                                      "js", "css", "static", "assets", "docs", "documentation"]
                        f.write("\n".join(common_dirs))
                    wordlist = temp_wordlist
            
            # Run gobuster for directory enumeration
            cmd = f"gobuster dir -u {protocol}://{self.target}:{port} -w {wordlist} -o {results_file} -t 50"
            if protocol == "https":
                cmd += " -k"  # Skip TLS verification for https
                
            # Add more extensions to check
            cmd += " -x php,html,txt,asp,aspx,jsp,cgi"
            
            self.console.print(f"[yellow]Running: {cmd}[/yellow]")
            
            # Run the command and capture output
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Start a spinner to show progress
            with self.console.status("[bold green]Bruteforcing directories...[/bold green]") as status:
                interesting_finds = []
                
                for line in proc.stdout:
                    if "Status:" in line and ("200" in line or "301" in line or "302" in line or "403" in line):
                        interesting_finds.append(line.strip())
                        # Update status with latest finding
                        status.update(f"[bold green]Found: {line.strip()}[/bold green]")
                
                proc.communicate()  # Ensure process completes
            
            # Display interesting findings
            if interesting_finds:
                self.console.print("[bold cyan]Interesting directories found:[/bold cyan]")
                for find in interesting_finds:
                    self.console.print(f"- {find}")
                
                # Add to enumeration results
                if "web" not in self.enumeration.results:
                    self.enumeration.results["web"] = {}
                
                if "directories" not in self.enumeration.results["web"]:
                    self.enumeration.results["web"]["directories"] = []
                
                # Parse and add findings to results
                for find in interesting_finds:
                    parts = find.split()
                    url = None
                    status = None
                    
                    for part in parts:
                        if part.startswith(f"{protocol}://"):
                            url = part
                        elif part.startswith("Status:"):
                            status = part.replace("Status:", "").strip()
                    
                    if url and status:
                        self.enumeration.results["web"]["directories"].append({
                            "url": url,
                            "status": status
                        })
            
            self.console.print(f"[green]Web directory brute-force complete. Results saved to {results_file}[/green]")
            
        except Exception as e:
            self.logger.error(f"Error during web directory brute-force: {str(e)}")
            self.console.print(f"[bold red]Error during web directory brute-force: {str(e)}[/bold red]") 