import logging
import os
from rich.logging import RichHandler

def setup_logger(name: str) -> logging.Logger:
    """
    Sets up a logger that logs to both a file and the rich console.
    """
    if not os.path.exists("logs"):
        os.makedirs("logs")

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # File handler for detailed debug logs
        file_handler = logging.FileHandler("logs/cybershield.log", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_format)
        
        # Rich handler for console (warnings/errors mostly or debug if needed)
        console_handler = RichHandler(rich_tracebacks=True, markup=True)
        console_handler.setLevel(logging.WARNING) # Only log warnings and errors to console by default
        console_format = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_format)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
