"""
Logging module for RedFlow
// מודול לניהול לוגים עבור RedFlow
"""

import os
import sys
import logging
from rich.logging import RichHandler
from rich.console import Console


def setup_logger(project_dir, verbose=False):
    """
    Set up a rich-based logger for system actions
    // הגדרת לוגר מבוסס rich לרישום פעולות המערכת
    
    Args:
        project_dir: Project directory path
        verbose: Whether to display detailed logs
        
    Returns:
        Configured logger
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(project_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Set log file
    log_file = os.path.join(log_dir, "redflow.log")
    
    # Set logging level based on verbose parameter
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Configure logger
    logger = logging.getLogger("redflow")
    logger.setLevel(log_level)
    logger.propagate = False  # Prevent propagation to parent logger
    
    # Check if there are already handlers and clear them
    if logger.handlers:
        logger.handlers.clear()
    
    # Add file handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(log_level)
    logger.addHandler(file_handler)
    
    # Add Rich-based console handler
    console_handler = RichHandler(
        rich_tracebacks=True,
        console=Console(stderr=True),
        tracebacks_show_locals=verbose
    )
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)
    
    # Log initialization message
    logger.info("RedFlow initialized. Version: 0.1.0")
    if verbose:
        logger.debug("Verbose logging mode enabled")
    
    return logger


class LoggerAdapter(logging.LoggerAdapter):
    """Adapter to add prefixes to each log message, e.g., adding a module name or action identifier"""
    
    def __init__(self, logger, prefix):
        """
        Initialize logger adapter
        // אתחול מתאם הלוגר
        
        Args:
            logger: Base logger instance
            prefix: Prefix to add to each log message
        """
        super().__init__(logger, {})
        self.prefix = prefix
    
    def process(self, msg, kwargs):
        """Add prefix to log message"""
        return f"[{self.prefix}] {msg}", kwargs


def get_module_logger(module_name, logger):
    """
    Returns a logger adapted for a specific module
    // מחזיר לוגר מותאם למודול ספציפי
    
    Args:
        module_name: Module name
        logger: Base logger
        
    Returns:
        Logger adapter with module name prefix
    """
    return LoggerAdapter(logger, module_name) 