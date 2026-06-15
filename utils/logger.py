"""
Logging configuration for CyberShield Toolkit.

Sets up a dual-output logger that writes detailed debug logs to a
rotating file and only surfaces warnings and above to the console
via rich markup. Log level can be overridden with the
``CYBERSHIELD_LOG_LEVEL`` environment variable.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler


_LOG_DIR = "logs"
_LOG_FILE = os.path.join(_LOG_DIR, "cybershield.log")
_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
_BACKUP_COUNT = 3
_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """
    Create or retrieve a named logger with file and console handlers.

    On first call for a given *name*, two handlers are attached:

    * **RotatingFileHandler** – writes all DEBUG-level messages to
      ``logs/cybershield.log`` with automatic rotation at 5 MB.
    * **RichHandler** – renders WARNING+ messages to the terminal.
      When *verbose* is ``True`` the console threshold drops to DEBUG.

    Subsequent calls with the same *name* return the cached logger
    without adding duplicate handlers.

    Args:
        name: Logger namespace (typically the module name).
        verbose: If True, console output includes DEBUG messages.

    Returns:
        A fully configured :class:`logging.Logger` instance.
    """
    env_level = os.environ.get("CYBERSHIELD_LOG_LEVEL", "").upper()
    log_level = getattr(logging, env_level, logging.DEBUG)

    os.makedirs(_LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    if logger.handlers:
        return logger

    # Rotating file handler
    file_handler = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    # Rich console handler
    console_level = logging.DEBUG if verbose else logging.WARNING
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_time=False,
        show_path=False,
    )
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
