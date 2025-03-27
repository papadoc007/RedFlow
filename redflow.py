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
    if not target and not args.run_msfconsole:
        metadata_file = os.path.join(args.results_dir, "metadata.json")
        if os.path.exists(metadata_file):
            import json
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    target = metadata.get("target")
            except:
                pass
    
    if not target and not args.run_msfconsole:
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

def main():
    """Main program function // הפונקציה הראשית של התוכנית"""
    args = parse_args()
    
    # Create project directory and initialize log files
    if args.target:
        project_dir = init_project_dir(args.target, args.output)
    else:
        # For file operations, we might not have a target
        project_dir = args.results_dir or os.path.expanduser(args.output)
        if not os.path.exists(project_dir):
            os.makedirs(project_dir, exist_ok=True)
    
    logger = setup_logger(project_dir, args.verbose)
    console = Console()
    
    try:
        # Check if we're doing file operations instead of a scan
        if args.list_files or args.download_url or args.view_url or args.interactive_download:
            handle_file_operations(args, logger, console)
            return
        
        # Check if we're doing exploit operations
        if args.exploit_menu or args.search_exploits or args.service_to_exploit or args.run_msfconsole:
            handle_exploit_operations(args, logger, console)
            return
        
        # Make sure we have a target for regular scanning
        if not args.target:
            logger.error("Target is required for scanning. Use --target option.")
            console.print("[bold red]Target is required for scanning. Use --target option.[/bold red]")
            console.print("For file operations on previous scans, use --list-files, --download, --interactive-download, or --view")
            console.print("For exploit operations, use --exploit-menu, --search-exploits, or --service-to-exploit")
            console.print("To start msfconsole directly, use --msfconsole")
            return
        
        # Check system requirements
        check_requirements(logger)
        
        # Initialize configuration
        config = Config(args, project_dir)
        
        # Create scanner
        scanner = Scanner(config, logger, console)
        
        # Start scanning
        scanner.start()
        
    except KeyboardInterrupt:
        logger.info("RedFlow manually stopped by user")
        console.print("[bold red]RedFlow manually stopped by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        console.print(f"[bold red]Unexpected error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 