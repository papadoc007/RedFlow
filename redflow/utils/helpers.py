"""
General helper functions for RedFlow
// פונקציות עזר כלליות עבור RedFlow
"""

import os
import sys
import shutil
import json
import re
import socket
import subprocess
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
import importlib
import errno


def is_valid_ip(ip):
    """
    Check if the string is a valid IP address
    // בדיקה האם המחרוזת היא כתובת IP תקינה
    
    Args:
        ip: String to check
        
    Returns:
        Boolean: Whether the string is a valid IP
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if not re.match(pattern, ip):
        return False
    
    # Verify that each octet is between 0-255
    for octet in ip.split('.'):
        if int(octet) > 255:
            return False
    
    return True


def is_valid_domain(domain):
    """
    Check if the string is a valid domain name
    // בדיקה האם המחרוזת היא דומיין תקין
    
    Args:
        domain: String to check
        
    Returns:
        Boolean: Whether the string is a valid domain
    """
    pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain, re.IGNORECASE))


def init_project_dir(target, base_output_dir="./scans/"):
    """
    Create project directory structure
    // יצירת מבנה תיקיות הפרויקט
    
    Args:
        target: IP address or domain
        base_output_dir: Base path for output directory
        
    Returns:
        Path to project directory
    """
    # Clean target name for use as directory name
    target_name = target.replace('.', '_').replace(':', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Create unique directory name for target
    project_name = f"RedFlow_{target_name}_{timestamp}"
    project_dir = os.path.join(os.path.expanduser(base_output_dir), project_name)
    
    # Create relevant directories
    os.makedirs(project_dir, exist_ok=True)
    os.makedirs(os.path.join(project_dir, "scans"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "summaries"), exist_ok=True)
    
    console = Console()
    console.print(f"[bold green]Creating new project:[/bold green] {project_dir}")
    
    return project_dir


def is_tool_available(name):
    """
    Check if a specific tool is available in the system path
    // בדיקה האם כלי ספציפי זמין בנתיב המערכת
    
    Args:
        name: Tool name to check
        
    Returns:
        True if tool is available
    """
    try:
        devnull = subprocess.DEVNULL
        subprocess.Popen([name, "--help"], stdout=devnull, stderr=devnull).communicate()
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
    return True


def is_python_package_installed(package_name):
    """
    Check if a specific Python package is installed
    
    Args:
        package_name: Package name to check
        
    Returns:
        True if package is installed
    """
    try:
        importlib.import_module(package_name)
        return True
    except ImportError:
        return False


def check_requirements(logger):
    """
    Check system requirements and required tools
    // בדיקת דרישות המערכת וקיום הכלים הנדרשים
    
    Args:
        logger: Logger instance
        
    Returns:
        True if all requirements are met
    """
    # Tools that need to be installed
    essential_tools = ["nmap", "whois", "dig"]
    optional_tools = ["enum4linux", "hydra", "gobuster", "theHarvester", "sublist3r", "whatweb", "wafw00f"]
    
    # Python packages
    essential_packages = ["requests"]
    optional_packages = ["ftputil"]
    
    missing_tools = []
    
    # Check essential tools
    for tool in essential_tools:
        if not is_tool_available(tool):
            missing_tools.append(tool)
    
    # Check essential Python packages
    for package in essential_packages:
        if not is_python_package_installed(package):
            missing_tools.append(f"Python package: {package}")
    
    if missing_tools:
        logger.error(f"Missing essential tools: {', '.join(missing_tools)}")
        logger.error("Please install missing tools before running RedFlow")
        console = Console()
        console.print(Panel.fit(
            f"[bold red]Missing essential tools:[/bold red] {', '.join(missing_tools)}\n"
            f"Please install missing tools before running RedFlow", 
            title="Error"
        ))
        sys.exit(1)
    
    # Check optional tools
    optional_missing = []
    for tool in optional_tools:
        if not is_tool_available(tool):
            optional_missing.append(tool)
    
    # Check optional Python packages
    for package in optional_packages:
        if not is_python_package_installed(package):
            optional_missing.append(f"Python package: {package}")
    
    if optional_missing:
        logger.warning(f"Missing optional tools/packages: {', '.join(optional_missing)}")
        logger.warning("Some features may not work without these tools/packages")
        console = Console()
        console.print(Panel.fit(
            f"[bold yellow]Missing optional tools/packages:[/bold yellow] {', '.join(optional_missing)}\n"
            f"Some features may not work without these tools/packages\n\n"
            f"To install missing Python packages, run:\n"
            f"[green]pip install {' '.join([p.replace('Python package: ', '') for p in optional_missing if p.startswith('Python package:')])}"
            if any(p.startswith('Python package:') for p in optional_missing) else "",
            title="Warning"
        ))
    
    return True


def get_target_info(target):
    """
    Extract basic information about a target (IP or domain)
    // מוציא מידע בסיסי על מטרה (IP או דומיין)
    
    Args:
        target: IP address or domain
        
    Returns:
        Dictionary with target information
    """
    info = {"original": target}
    
    # Check if it's an IP or domain
    if is_valid_ip(target):
        info["type"] = "ip"
        info["ip"] = target
        try:
            hostname, _, _ = socket.gethostbyaddr(target)
            info["hostname"] = hostname
        except (socket.herror, socket.gaierror):
            info["hostname"] = None
    elif is_valid_domain(target):
        info["type"] = "domain"
        info["domain"] = target
        try:
            info["ip"] = socket.gethostbyname(target)
        except socket.gaierror:
            info["ip"] = None
    else:
        info["type"] = "unknown"
    
    return info


def run_tool(cmd, output_file=None, timeout=300, shell=False):
    """
    Run an external tool and optionally save the output
    // הרצת כלי חיצוני ובמידת הצורך שמירת הפלט
    
    Args:
        cmd: Command to run (string or list)
        output_file: Path to output file (optional)
        timeout: Maximum execution time in seconds
        shell: Whether to run in a shell
        
    Returns:
        Dictionary with the tool's output
    """
    # Prepare the command
    if isinstance(cmd, list):
        cmd_str = " ".join(cmd)
    else:
        cmd_str = cmd
        if not shell:
            cmd = cmd.split()
    
    result = {
        "command": cmd_str,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None,
        "timeout": False
    }
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        result["returncode"] = process.returncode
        result["stdout"] = stdout
        result["stderr"] = stderr
        
        # Save to file if specified
        if output_file and stdout:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(stdout)
                
                # Add information about executed command at beginning of file
                f.write(f"\n\n# Command: {cmd_str}\n")
                f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
    
    except subprocess.TimeoutExpired:
        process.kill()
        result["timeout"] = True
        result["error"] = f"Command terminated after {timeout} seconds"
    
    except Exception as e:
        result["error"] = str(e)
    
    return result 