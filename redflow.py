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
        choices=["passive", "active", "full"],
        default="full",
        help="Scan mode (passive, active, or full)"
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
        "--port",
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
        
        # Make sure we have a target for regular scanning
        if not args.target:
            logger.error("Target is required for scanning. Use --target option.")
            console.print("[bold red]Target is required for scanning. Use --target option.[/bold red]")
            console.print("For file operations on previous scans, use --list-files, --download, --interactive-download, or --view")
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