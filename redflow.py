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
        required=True
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
    
    return parser.parse_args()

def main():
    """Main program function // הפונקציה הראשית של התוכנית"""
    args = parse_args()
    
    # Create project directory and initialize log files
    project_dir = init_project_dir(args.target, args.output)
    logger = setup_logger(project_dir, args.verbose)
    console = Console()
    
    try:
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