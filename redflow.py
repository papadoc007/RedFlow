#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RedFlow - Advanced Automated Information Gathering and Attack Tool for Kali Linux
// מידע: כלי אוטומטי מתקדם לאיסוף מידע ותקיפה לסביבת Kali Linux
"""

import argparse
import os
import sys
import logging
import re
import socket
from rich.console import Console
from rich.logging import RichHandler

from redflow.core.scanner import Scanner
from redflow.modules.enumeration import Enumeration
from redflow.utils.logger import setup_logger
from redflow.utils.config import Config
from redflow.utils.helpers import check_requirements, init_project_dir

__version__ = "0.1.0"

def parse_args():
    """Function to process command-line arguments // פונקציה לעיבוד פרמטרים מהמשתמש"""
    parser = argparse.ArgumentParser(
        description="RedFlow - Advanced Automated Information Gathering and Attack Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--target", "-t",
        dest="target",
        help="IP address or domain name of the target",
        required=False
    )
    
    parser.add_argument(
        "--mode", "-m",
        dest="mode",
        choices=["passive", "active", "full", "quick"],
        default="full",
        help="Scan mode (passive, active, full, or quick - quick performs port scan and directory enumeration without vulnerability checks)"
    )
    
    parser.add_argument(
        "--port", "-p",
        dest="specific_port",
        type=int,
        help="Scan and focus on a specific port (e.g., 21 for FTP)"
    )
    
    parser.add_argument(
        "--output", "-o",
        dest="output",
        default="./scans/",
        help="Path to output directory"
    )
    
    parser.add_argument(
        "--interactive", "-i",
        dest="interactive",
        action="store_true",
        help="Prompt for confirmation before proceeding to the next phase"
    )
    
    parser.add_argument(
        "--gpt",
        dest="use_gpt",
        action="store_true",
        help="Use GPT-4 for recommendations (requires API key)"
    )
    
    parser.add_argument(
        "--gpt-model",
        dest="gpt_model",
        choices=["gpt-4o-mini", "gpt-4", "gpt-3.5-turbo"],
        default="gpt-4o-mini",
        help="Specify which GPT model to use for analysis (default: gpt-4o-mini)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        dest="verbose",
        action="store_true",
        help="Enable verbose logging level"
    )
    
    parser.add_argument(
        "--no-vulns",
        dest="scan_vulns",
        action="store_false",
        help="Skip vulnerability scanning (faster execution)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"RedFlow v{__version__}"
    )

    # Add file operations related arguments
    file_operations = parser.add_argument_group('File Operations')
    
    file_operations.add_argument(
        "--list-files",
        dest="list_files",
        action="store_true",
        help="List discovered files from a previous scan"
    )
    
    file_operations.add_argument(
        "--interactive-download",
        dest="interactive_download",
        action="store_true",
        help="Interactively select and download discovered files"
    )
    
    file_operations.add_argument(
        "--file-port",
        dest="port",
        type=int,
        default=80,
        help="Port to use for file operations (default: 80)"
    )
    
    file_operations.add_argument(
        "--protocol",
        dest="protocol",
        choices=["http", "https", "ftp"],
        default="http",
        help="Protocol to use for file operations"
    )
    
    file_operations.add_argument(
        "--download",
        dest="download_url",
        help="URL or path of file to download"
    )
    
    file_operations.add_argument(
        "--view",
        dest="view_url",
        help="URL or path of file to view"
    )
    
    file_operations.add_argument(
        "--results-dir",
        dest="results_dir",
        help="Directory of previous scan results to use for file operations"
    )
    
    # Add vulnerability exploitation related arguments
    exploit_operations = parser.add_argument_group('Vulnerability Exploitation')
    
    exploit_operations.add_argument(
        "--exploit-menu",
        dest="exploit_menu",
        action="store_true",
        help="Show interactive exploit menu for discovered services"
    )
    
    exploit_operations.add_argument(
        "--search-exploits",
        dest="search_exploits",
        help="Search for exploits for a specific service (format: service:version)"
    )
    
    exploit_operations.add_argument(
        "--port-to-exploit",
        dest="port_to_exploit",
        type=int,
        help="Port of the service to exploit"
    )
    
    exploit_operations.add_argument(
        "--service-to-exploit",
        dest="service_to_exploit",
        help="Name of the service to exploit (e.g. vsftpd, apache)"
    )
    
    exploit_operations.add_argument(
        "--msfconsole",
        dest="run_msfconsole",
        action="store_true",
        help="Start Metasploit console directly and optionally target a specific IP"
    )
    
    # Add new argument for GPT exploit advisor
    exploit_operations.add_argument(
        "--gpt-advisor",
        dest="gpt_advisor",
        action="store_true",
        help="Use GPT to analyze and suggest exploits for detected services"
    )
    
    # Add new argument for interactive menu
    parser.add_argument(
        "--menu",
        dest="interactive_menu",
        action="store_true",
        help="Launch interactive menu-driven interface"
    )
    
    return parser.parse_args()

def handle_file_operations(args, logger, console):
    """
    Handle file operation requests
    
    Args:
        args: Command line arguments
        logger: Logger instance
        console: Console instance
    """
    # Find the most recent scan directory if results_dir not specified
    if not args.results_dir:
        scans_base = os.path.expanduser(args.output)
        target_dirs = []
        
        if os.path.exists(scans_base):
            for dirname in os.listdir(scans_base):
                full_path = os.path.join(scans_base, dirname)
                if os.path.isdir(full_path) and "RedFlow_" in dirname:
                    target_dirs.append((full_path, os.path.getmtime(full_path)))
        
        if target_dirs:
            # Sort by creation time (newest first)
            target_dirs.sort(key=lambda x: x[1], reverse=True)
            args.results_dir = target_dirs[0][0]
            logger.info(f"Using most recent results directory: {args.results_dir}")
        else:
            logger.error("No previous scan results found. Please specify --results-dir")
            console.print("[bold red]No previous scan results found. Please specify --results-dir[/bold red]")
            return
    
    # Initialize configuration
    temp_args = argparse.Namespace()
    temp_args.target = args.target or "localhost"  # Placeholder target if none provided
    temp_args.mode = "passive"
    temp_args.output = args.results_dir
    temp_args.interactive = False
    temp_args.use_gpt = False
    temp_args.verbose = args.verbose
    
    config = Config(temp_args, args.results_dir)
    
    # Initialize enumeration module
    enumeration = Enumeration(config, logger, console)
    
    # Determine target from results dir if not provided
    target = args.target
    if not target:
        metadata_file = os.path.join(args.results_dir, "metadata.json")
        if os.path.exists(metadata_file):
            import json
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    target = metadata.get("target")
            except:
                pass
    
    if not target:
        logger.error("Target not specified and could not be determined from scan results")
        console.print("[bold red]Target not specified and could not be determined from scan results[/bold red]")
        return
    
    # Load previous results if they exist
    results_file = os.path.join(args.results_dir, "results.json")
    if os.path.exists(results_file):
        import json
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
                # Load web enumeration results
                if "enumeration" in results and "web" in results["enumeration"]:
                    enumeration.results["web"] = results["enumeration"]["web"]
        except Exception as e:
            logger.error(f"Error loading previous results: {str(e)}")
    
    # Set target for enumeration
    enumeration.target = target
    
    # Handle the file operations
    if args.list_files:
        enumeration.list_discovered_files(target, args.port, args.protocol)
    
    if args.interactive_download:
        console.print(f"[bold green]Interactive file download for {target}:[/bold green]")
        enumeration.interactive_download_files(target, args.port, args.protocol)
    
    if args.download_url:
        enumeration.download_file(args.download_url)
    
    if args.view_url:
        enumeration.view_web_file_content(url=args.view_url)

def handle_exploit_operations(args, logger, console):
    """
    Handle exploit operation requests
    
    Args:
        args: Command line arguments
        logger: Logger instance
        console: Console instance
    """
    # Find the most recent scan directory if results_dir not specified
    if not args.results_dir:
        scans_base = os.path.expanduser(args.output)
        target_dirs = []
        
        if os.path.exists(scans_base):
            for dirname in os.listdir(scans_base):
                full_path = os.path.join(scans_base, dirname)
                if os.path.isdir(full_path) and "RedFlow_" in dirname:
                    target_dirs.append((full_path, os.path.getmtime(full_path)))
        
        if target_dirs:
            # Sort by creation time (newest first)
            target_dirs.sort(key=lambda x: x[1], reverse=True)
            args.results_dir = target_dirs[0][0]
            logger.info(f"Using most recent results directory: {args.results_dir}")
        else:
            logger.error("No previous scan results found. Please specify --results-dir")
            console.print("[bold red]No previous scan results found. Please specify --results-dir[/bold red]")
            return
    
    # Initialize configuration
    temp_args = argparse.Namespace()
    temp_args.target = args.target or "localhost"  # Placeholder target if none provided
    temp_args.mode = "passive"
    temp_args.output = args.results_dir
    temp_args.interactive = False
    temp_args.use_gpt = False
    temp_args.verbose = args.verbose
    
    config = Config(temp_args, args.results_dir)
    
    # Initialize enumeration module
    enumeration = Enumeration(config, logger, console)
    
    # Determine target from results dir if not provided
    target = args.target
    if not target and not args.run_msfconsole and not args.gpt_advisor:
        metadata_file = os.path.join(args.results_dir, "metadata.json")
        if os.path.exists(metadata_file):
            import json
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    target = metadata.get("target")
            except:
                pass
    
    if not target and not args.run_msfconsole and not args.gpt_advisor:
        logger.error("Target not specified and could not be determined from scan results")
        console.print("[bold red]Target not specified and could not be determined from scan results[/bold red]")
        return
    
    # Load previous results if they exist
    found_services = []
    results_file = os.path.join(args.results_dir, "results.json")
    if os.path.exists(results_file):
        import json
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
                
                # Load discovered services from scan results
                if "discovered_services" in results:
                    found_services = results["discovered_services"]
                    
                # Load enumeration results
                if "enumeration" in results:
                    for key, value in results["enumeration"].items():
                        enumeration.results[key] = value
                        
        except Exception as e:
            logger.error(f"Error loading previous results: {str(e)}")
    
    # Set target for enumeration
    enumeration.target = target
    
    # Check if we want to use the GPT exploit advisor
    if args.gpt_advisor:
        # Import the GPT exploit advisor
        try:
            from redflow.modules.gpt.exploit_advisor import ExploitAdvisor
            
            console.print(f"[bold green]Starting GPT Exploit Advisor[/bold green]")
            
            # Initialize the advisor
            advisor = ExploitAdvisor(config, logger, console)
            
            # Run the interactive advisor
            advisor.interactive_exploit_advisor(found_services)
            
            return
        except ImportError as e:
            logger.error(f"Error importing GPT Exploit Advisor: {e}")
            console.print("[bold red]Error: Could not import GPT Exploit Advisor module[/bold red]")
            console.print("[bold yellow]Make sure you have all required dependencies installed[/bold yellow]")
            return
        except Exception as e:
            logger.error(f"Error running GPT Exploit Advisor: {e}")
            console.print(f"[bold red]Error running GPT Exploit Advisor: {e}[/bold red]")
            return
    
    # Check if we want to run msfconsole directly
    if args.run_msfconsole:
        console.print(f"[bold green]Starting Metasploit Console{' targeting ' + target if target else ''}[/bold green]")
        enumeration.run_msfconsole(target)
        return
    
    # Check if we're searching for exploits for a specific service
    if args.search_exploits:
        if ":" in args.search_exploits:
            service, version = args.search_exploits.split(":", 1)
            console.print(f"[bold green]Searching exploits for {service} {version}:[/bold green]")
            enumeration.find_vulnerabilities_with_searchsploit(service, version)
        else:
            console.print("[bold yellow]Format should be service:version (e.g. vsftpd:2.3.4)[/bold yellow]")
            return
    
    # Check if we're exploiting a specific service
    elif args.service_to_exploit and args.port_to_exploit:
        service_type = None
        service_name = args.service_to_exploit
        version = ""
        port = str(args.port_to_exploit)
        
        # Try to find the service details in discovered services
        for service in found_services:
            if str(service.get("port")) == port:
                service_type = service.get("name", "").lower()
                version = service.get("version", "")
                break
        
        # If we didn't find in discovered services, try to determine from port
        if not service_type:
            common_ports = {
                "21": "ftp",
                "22": "ssh",
                "25": "smtp",
                "80": "http",
                "443": "https",
                "445": "microsoft-ds",
                "3306": "mysql",
                "5432": "postgresql"
            }
            service_type = common_ports.get(port, "unknown")
        
        console.print(f"[bold green]Exploiting {service_name} on port {port}:[/bold green]")
        enumeration.interactive_exploit_menu(service_type, service_name, version, target)
    
    # Otherwise show exploit menu for all discovered services
    elif args.exploit_menu:
        if not found_services:
            console.print("[bold yellow]No discovered services found in scan results.[/bold yellow]")
            console.print("Run a scan first with: python redflow.py --target TARGET --mode full")
            return
        
        console.print("\n[bold green]Discovered Services:[/bold green]")
        for i, service in enumerate(found_services, 1):
            port = service.get("port", "")
            name = service.get("name", "").lower()
            version = service.get("version", "")
            console.print(f"{i}. [bold cyan]{name}[/bold cyan] on port {port} - Version: {version}")
        
        console.print("\n[bold]Enter the number of the service to exploit (or 'q' to quit):[/bold]")
        selection = input("> ").strip().lower()
        
        if selection == "q":
            return
        
        try:
            idx = int(selection)
            if 1 <= idx <= len(found_services):
                selected = found_services[idx-1]
                service_type = selected.get("name", "").lower()
                service_name = service_type
                version = selected.get("version", "")
                port = selected.get("port", "")
                
                # Special case: use product name if available
                if "product" in selected:
                    service_name = selected["product"].lower()
                
                console.print(f"[bold green]Selected: {service_name} {version} on port {port}[/bold green]")
                enumeration.interactive_exploit_menu(service_type, service_name, version, target)
            else:
                console.print("[bold red]Invalid selection.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid input. Please enter a number.[/bold red]")
    
    else:
        console.print("[bold yellow]No exploit operation specified.[/bold yellow]")
        console.print("Use --exploit-menu to select from discovered services")
        console.print("Or use --search-exploits SERVICE:VERSION to search for exploits")
        console.print("Or use --service-to-exploit SERVICE --port-to-exploit PORT to exploit a specific service")

def is_valid_ip(ip):
    """
    Validate if the string is a valid IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        # Simple pattern for IPv4 validation
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        
        if not match:
            return False
            
        # Validate each octet
        for octet in match.groups():
            if int(octet) > 255:
                return False
                
        return True
    except:
        return False

def is_valid_domain(domain):
    """
    Validate if the string is a potentially valid domain name
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if potentially valid domain name, False otherwise
    """
    try:
        # Simple pattern for domain validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if re.match(pattern, domain):
            return True
            
        # Try to resolve the domain as a fallback
        socket.gethostbyname(domain)
        return True
    except:
        return False

def interactive_menu():
    """
    Interactive menu-driven interface for RedFlow
    
    Returns:
        argparse.Namespace: Arguments namespace with user selections
    """
    console = Console()
    console.print("\n[bold blue]=====================================[/bold blue]")
    console.print("[bold blue]     RedFlow Interactive Menu       [/bold blue]")
    console.print("[bold blue]=====================================[/bold blue]\n")
    
    # Create an empty args object
    args = argparse.Namespace()
    
    # Step 1: Target Selection
    console.print("[bold cyan]Step 1: Target Selection[/bold cyan]")
    target_type = console.input("[green]Choose target type ([white]1[/white]: IP Address, [white]2[/white]: Domain): [/green]")
    
    if target_type == "1":
        while True:
            target = console.input("[green]Enter IP address: [/green]")
            if is_valid_ip(target):
                break
            else:
                console.print("[red]Invalid IP address. Please try again.[/red]")
    else:
        while True:
            target = console.input("[green]Enter domain name: [/green]")
            if is_valid_domain(target):
                break
            else:
                console.print("[red]Invalid domain name. Please try again.[/red]")
    
    args.target = target
    
    # Step 2: Port Selection
    console.print("\n[bold cyan]Step 2: Port Selection[/bold cyan]")
    port_option = console.input("[green]Choose port option ([white]1[/white]: Specific port, [white]2[/white]: All ports): [/green]")
    
    if port_option == "1":
        while True:
            try:
                port = int(console.input("[green]Enter port number: [/green]"))
                if 1 <= port <= 65535:
                    args.specific_port = port
                    break
                else:
                    console.print("[red]Port must be between 1 and 65535.[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number.[/red]")
    else:
        args.specific_port = None
    
    # Step 3: Scan Mode
    console.print("\n[bold cyan]Step 3: Scan Mode[/bold cyan]")
    console.print("[white]Available scan modes:[/white]")
    console.print("  [white]1[/white]: Passive - Gathers information without direct interaction")
    console.print("  [white]2[/white]: Active - Port scanning and basic service detection")
    console.print("  [white]3[/white]: Full - Complete scan including vulnerability detection")
    console.print("  [white]4[/white]: Quick - Fast scan focusing on open ports")
    
    scan_mode = console.input("[green]Choose scan mode [1-4]: [/green]")
    if scan_mode == "1":
        args.mode = "passive"
    elif scan_mode == "2":
        args.mode = "active"
    elif scan_mode == "4":
        args.mode = "quick"
    else:
        args.mode = "full"  # Default to full
    
    # Step 4: Additional Options
    console.print("\n[bold cyan]Step 4: Additional Options[/bold cyan]")
    
    # Interactive mode
    interactive = console.input("[green]Enable interactive mode (confirm before proceeding)? (y/n): [/green]").lower()
    args.interactive = interactive.startswith("y")
    
    # Verbose output
    verbose = console.input("[green]Enable verbose output? (y/n): [/green]").lower()
    args.verbose = verbose.startswith("y")
    
    # GPT integration
    gpt = console.input("[green]Use GPT for analysis (requires API key)? (y/n): [/green]").lower()
    args.use_gpt = gpt.startswith("y")
    
    # GPT Exploit Advisor
    gpt_advisor = console.input("[green]Enable GPT Exploit Advisor for vulnerability assessment? (y/n): [/green]").lower()
    args.gpt_advisor = gpt_advisor.startswith("y")
    
    # Ask for OpenAI API key if either GPT option is enabled
    if args.use_gpt or args.gpt_advisor:
        # Check if API key already exists
        api_key = os.environ.get("OPENAI_API_KEY", "")
        key_file = os.path.expanduser('~/.openai_api_key')
        
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                saved_key = f.read().strip()
                if saved_key and len(saved_key) > 10:
                    api_key = saved_key
        
        if not api_key or len(api_key) < 10:
            console.print("\n[bold cyan]OpenAI API Key Setup[/bold cyan]")
            console.print("[yellow]An OpenAI API key is required for GPT analysis.[/yellow]")
            api_key = console.input("[green]Enter your OpenAI API key: [/green]").strip()
            
            if api_key and len(api_key) > 10:
                # Ask if they want to save it
                save_key = console.input("[green]Save this API key for future use? (y/n): [/green]").lower()
                if save_key.startswith("y"):
                    with open(key_file, 'w') as f:
                        f.write(api_key)
                    console.print("[green]API key saved to ~/.openai_api_key[/green]")
                
                # Set environment variable for current session
                os.environ["OPENAI_API_KEY"] = api_key
            else:
                console.print("[bold red]Invalid API key. GPT features may not work correctly.[/bold red]")
        
        # GPT model selection
        console.print("\n[bold cyan]GPT Model Selection[/bold cyan]")
        console.print("[white]Available models:[/white]")
        console.print("  [white]1[/white]: gpt-4o-mini (Recommended - fast, cost-effective)")
        console.print("  [white]2[/white]: gpt-4 (More capable but slower and more expensive)")
        console.print("  [white]3[/white]: gpt-3.5-turbo (Legacy model, less capable)")
        
        model_selection = console.input("[green]Choose GPT model [1-3] (default: 1): [/green]")
        
        if model_selection == "2":
            args.gpt_model = "gpt-4"
        elif model_selection == "3":
            args.gpt_model = "gpt-3.5-turbo"
        else:
            args.gpt_model = "gpt-4o-mini"  # Default to gpt-4o-mini
            
        console.print(f"[green]Selected model: {args.gpt_model}[/green]")
    
    # Output directory
    default_output = "./scans/"
    output_dir = console.input(f"[green]Enter output directory (default: {default_output}): [/green]")
    args.output = output_dir if output_dir else default_output
    
    # Initialize remaining required attributes with default values
    args.scan_vulns = True
    args.list_files = False
    args.interactive_download = False
    args.port = 80
    args.protocol = "http"
    args.download_url = None
    args.view_url = None
    args.results_dir = None
    args.exploit_menu = False
    args.search_exploits = None
    args.port_to_exploit = None
    args.service_to_exploit = None
    args.run_msfconsole = False
    args.interactive_menu = True
    
    # Display summary of selections
    console.print("\n[bold cyan]Configuration Summary:[/bold cyan]")
    console.print(f"Target: [white]{args.target}[/white]")
    console.print(f"Port: [white]{args.specific_port if args.specific_port else 'All ports'}[/white]")
    console.print(f"Scan Mode: [white]{args.mode}[/white]")
    console.print(f"Interactive Mode: [white]{'Enabled' if args.interactive else 'Disabled'}[/white]")
    console.print(f"Verbose Output: [white]{'Enabled' if args.verbose else 'Disabled'}[/white]")
    console.print(f"GPT Analysis: [white]{'Enabled' if args.use_gpt else 'Disabled'}[/white]")
    console.print(f"GPT Exploit Advisor: [white]{'Enabled' if args.gpt_advisor else 'Disabled'}[/white]")
    console.print(f"Output Directory: [white]{args.output}[/white]")
    
    # Confirm and return
    confirm = console.input("\n[green]Proceed with these settings? (y/n): [/green]").lower()
    if not confirm.startswith("y"):
        console.print("[yellow]Configuration cancelled. Exiting...[/yellow]")
        sys.exit(0)
    
    return args

def get_logger():
    """
    Get a default logger instance for error handling
    """
    from rich.logging import RichHandler
    import logging
    
    # Setup a basic logger for error handling before we have a proper project directory
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    return logging.getLogger("redflow")

def main():
    """Main execution function // פונקציית ביצוע ראשית"""
    try:
        # Parse command-line arguments
        args = parse_args()
        
        # Get a basic logger for initial operations
        default_logger = get_logger()
        
        # Check if interactive menu was requested
        if hasattr(args, 'interactive_menu') and args.interactive_menu:
            args = interactive_menu()
        
        # Check requirements
        check_requirements(default_logger)
        
        # File operations
        if args.list_files or args.interactive_download or args.download_url or args.view_url:
            handle_file_operations(args, default_logger, Console())
            return
            
        # Exploit operations
        if args.exploit_menu or args.search_exploits or args.service_to_exploit or args.port_to_exploit or args.run_msfconsole or args.gpt_advisor:
            handle_exploit_operations(args, default_logger, Console())
            return
        
        # Validate target for regular scanning
        if not args.target:
            console = Console()
            default_logger.error("No target specified")
            console.print("[bold red]Error:[/bold red] No target specified. Use --target to specify a target or --help for more information.")
            return
            
        # Initialize project directory
        project_dir = init_project_dir(args.target, args.output)
        
        # Setup logger
        logger = setup_logger(project_dir, args.verbose)
        logger.info(f"RedFlow initialized. Version: {__version__}")
        
        # Create configuration object
        config = Config(args, project_dir)
        
        # Create scanner object
        scanner = Scanner(config, logger, Console())
        
        # Start scan process
        scanner.start()
        
    except KeyboardInterrupt:
        try:
            logger
        except NameError:
            logger = get_logger()
        logger.info("RedFlow manually stopped by user")
        Console().print("\n[bold yellow]RedFlow manually stopped by user[/bold yellow]")
    except Exception as e:
        try:
            logger
        except NameError:
            logger = get_logger()
        logger.error(f"An unexpected error occurred: {str(e)}")
        Console().print(f"\n[bold red]Error:[/bold red] An unexpected error occurred: {str(e)}")
        
if __name__ == "__main__":
    main() 