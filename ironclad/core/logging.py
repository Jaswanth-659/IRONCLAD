"""
IRONCLAD Core Logging Infrastructure.

Provides standardized, structured logging configuration across all engine modules.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

DEFAULT_LOG_FORMAT = (
    "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s"
)
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path | str] = None,
    enable_console: bool = True,
    propagate: bool = False,
) -> logging.Logger:
    """
    Configure the root 'ironclad' logger with stream and optional file handlers.

    Args:
        level: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional file destination for logs.
        enable_console: Whether to attach stdout stream handler.
        propagate: Whether child logs propagate to root Python logger.

    Returns:
        The configured 'ironclad' Logger instance.
    """
    logger = logging.getLogger("ironclad")
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    logger.propagate = propagate

    # Clear existing handlers to prevent duplicate lines
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(fmt=DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)

    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Retrieve a child logger under the 'ironclad' hierarchy.

    Args:
        name: Name of module or component (e.g. 'ironclad.ingestion.pcap_reader').

    Returns:
        A logging.Logger instance.
    """
    if not name.startswith("ironclad"):
        name = f"ironclad.{name}"
    return logging.getLogger(name)
