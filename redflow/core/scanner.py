"""
Central scanner module managing the scanning process
// מודול סורק מרכזי המנהל את תהליך הסריקה
"""

import os
import sys
import json
import time
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
   / __ \___  ___/ / / /___ _      __   
  / /_/ / _ \/ __/ / / / __ \ | /| / /   
 / _, _/  __/ /_/ / / / /_/ / |/ |/ /    
/_/ |_|\___/\__/_/_/_/\____/|__/|__/     
                                        
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
        
        if self.config.mode in ["active", "full"]:
            self.logger.info(f"Starting active information gathering for {self.config.target}")
            self.console.print("[bold blue]== Active Information Gathering ==[/bold blue]")
            
            active_results = self.active_recon.run()
            self.results["active_recon"] = active_results
            self.results["open_ports"] = active_results.get("open_ports", [])
            self.results["discovered_services"] = active_results.get("discovered_services", [])
            self.save_results()
            
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
        
        # Generate final report
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
                open_ports_table.add_row(
                    str(port_info["port"]), 
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