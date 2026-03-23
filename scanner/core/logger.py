# `scanner/core/logger.py`.
# Sets up logging for the whole scanner and every module pulls from this.
# Two outputs: a timestamped file (gets everything) and the console (INFO+ only, coloured).
# Keeping them separate allows for debugging of the log file without the terminal getting spammed with DEBUG noise mid-scan.
import logging
import os
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

# Without this, `ANSI` colour codes print as raw escape characters on Windows.
# `autoreset=True` means that the colour does not have to be manually reset after each line. 
colorama_init(autoreset=True)


class ColouredFormatter(logging.Formatter):
    # Maps each log level to a colour so that warnings can be spotted easily in the terminal without having to read the level label every time.
    LEVEL_COLOURS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        # Grab the colour for this level, fall back to no colour if unrecognised.
        colour = self.LEVEL_COLOURS.get(record.levelno, "")
        message = super().format(record)
        return f"{colour}{message}{Style.RESET_ALL}"


def setup_logger(
    name: str = "scanner",
    log_dir: str = "logs/",
    level: int = logging.DEBUG,
) -> logging.Logger:
    # Called once at startup from `main.py`. Everything else uses `get_logger()` from below.

    # Create `logs/` if it doesn't exist yet - this will happen on the first ever run.
    os.makedirs(log_dir, exist_ok=True)

    # Each scan gets its own log file to allow for run comparison without overwriting.
    # Format: `scan_2026-03-14_10-30-00.log`.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = os.path.join(log_dir, f"scan_{timestamp}.log")

    # File handler logs everything including DEBUG - useful for tracing exactly what requests were sent and what came back.
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    # Console handler only shows `INFO` and above, preventing every `HTTP` request from cluttering the terminal during a scan.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = ColouredFormatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    console_handler.setFormatter(console_formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    # `propagate=False` stops records from travelling to the root logger. Without this, every message would print twice.

    return logger


def get_logger(name: str) -> logging.Logger:
    """ Every sub-module (crawler, auth checker, IDOR tester, etc.,) calls this rather than a `setup_logger()`, so they all
    feed into the same handler chain that was setup at startup. Passing `__name__` gives each module its own label in the log 
    output, making tracing issues far easier."""
    return logging.getLogger(name)