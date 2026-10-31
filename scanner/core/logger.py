"""
`logger.py`

Sets up the scanners logging system thats used across the entire project. THe module provides two main, public, helper functions:
    `setup_logger`, which is called once from `main.py` when a scan begins to create the root `scanner` logger, with both a timestamped
    file, and a colour-coded console output.
    `get_logger`, which allows individual modules to create their own named child loggers, whilst still using the same shared logging
    configuration, and avoiding duplicate log entries.
"""

import logging
import os
import time
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

# print("logger boot")
# logging.basicConfig(level=logging.DEBUG)

# Enables ANSI colour support on the Windows terminal, so coloured output displays correctly. The autorest option automatically resets the terminal colour, aftrer each log message.
colorama_init(autoreset=True)


class ColouredFormatter(logging.Formatter):
    # Maps each logging level with a specific colour, so that important messages can be easily identified during a scan.
    LEVEL_COLOURS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED,
    }

    # DEFAULT_COLOUR = ""

    def format(self, record: logging.LogRecord) -> str:
        # Retrieves the colour for the current log level, and if no colour exists then it defaults back to displaying the message normally.
        colour = self.LEVEL_COLOURS.get(record.levelno, "")
        message = super().format(record)

        # if record.levelno == logging.DEBUG:
        #     print(record.msg)

        return f"{colour}{message}{Style.RESET_ALL}"


def setup_logger(
    name: str = "scanner",
    log_dir: str = "logs/",
    level: int = logging.DEBUG,
) -> logging.Logger:
    # Called once at startup from `main.py`. Everything else accesses the logger through `get_logger()` from below.

    # logger = logging.getLogger()
    # logger.handlers.clear()

    # Creates the log directory, if it doesn't already exist, on the first run of the scanner.
    os.makedirs(log_dir, exist_ok=True)

    # Creates a unique log file for each individual scan, in the format scan_2026-03-14_10-30-00.log`, to preserve previous svan runs, and allow for later comparison.
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = os.path.join(log_dir, f"scan_{timestamp}.log")

    # print(log_filename)

    # FIle handler records all the log messages, including te debug output. Makes it possible to trace requests, responses, and behavour during a san analysis.
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    # file_handler.setLevel(logging.INFO)

    # The consale handler only shows `INFO` and above, preventing every `HTTP` request from cluttering up tghe terminal during a scan.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = ColouredFormatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    console_handler.setFormatter(console_formatter)

    """ COnfigures both handlers to uce UTC timestamps, so the console output, log files, and san duration calculations all remain consistent. Without this, 
    timestamps may appear offset depending on the local timezone config, of the execution env."""

    file_handler.formatter.converter = time.gmtime
    console_handler.formatter.converter = time.gmtime

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # logger.handlers = []

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    # `propagate=False` prevents the log records from being passed to the root logger. WIthout this, every log message would appear twice in the console, and log file.

    # logger.debug("logger ready")

    return logger


def get_logger(name: str) -> logging.Logger:
    """Used by all the scanner modules e.g., the craler, authentication checks, and IDOR testing components. Each module retreves its own named logger, rather than
    creating a new logging configuration. PAssing `__name__` ensures that log entries are clearly labelled, making debugging and tracing execution behaviour easier."""

    # return setup_logger(name)

    return logging.getLogger(name)