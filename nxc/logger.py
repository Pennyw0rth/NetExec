import logging
from logging import LogRecord
from logging.handlers import RotatingFileHandler
import os.path
import sys
import re
from nxc.console import nxc_console
from termcolor import colored
from datetime import datetime
from rich.text import Text
from rich.logging import RichHandler
import functools
import inspect
import argparse


def parse_debug_args():
    debug_parser = argparse.ArgumentParser(add_help=False)
    debug_parser.add_argument("--debug", action="store_true")
    debug_parser.add_argument("--verbose", action="store_true")
    args, _ = debug_parser.parse_known_args()
    return args

def setup_debug_logging():
    debug_args = parse_debug_args()
    root_logger = logging.getLogger("root")
    
    if debug_args.verbose:
        nxc_logger.logger.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    elif debug_args.debug:
        nxc_logger.logger.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.INFO)
    else:
        nxc_logger.logger.setLevel(logging.ERROR)
        root_logger.setLevel(logging.ERROR)
        

def create_temp_logger(caller_frame, formatted_text, args, kwargs):
    """Create a temporary logger for emitting a log where we need to override the calling file & line number, since these are obfuscated"""
    temp_logger = logging.getLogger("temp")
    formatter = logging.Formatter("%(message)s", datefmt="[%X]")
    handler = SmartDebugRichHandler(formatter=formatter)
    handler.handle(LogRecord(temp_logger.name, logging.INFO, caller_frame.f_code.co_filename, caller_frame.f_lineno, formatted_text, args, kwargs, caller_frame=caller_frame))


class SmartDebugRichHandler(RichHandler):
    """Custom logging handler for when we want to log normal messages to DEBUG and not double log"""
    def __init__(self, formatter=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if formatter is not None:
            self.setFormatter(formatter)
            
    def emit(self, record):
        """Overrides the emit method of the RichHandler class so we can set the proper pathname and lineno"""
        # for some reason in RDP, the exc_text is None which leads to a KeyError in Python logging
        record.exc_text = record.getMessage() if record.exc_text is None else record.exc_text
        
        if hasattr(record, "caller_frame"):
            frame_info = inspect.getframeinfo(record.caller_frame)
            record.pathname = frame_info.filename
            record.lineno = frame_info.lineno
        super().emit(record)

def no_debug(func):
    """Stops logging non-debug messages when we are in debug mode
    It creates a temporary logger and logs the message to the console and file
    This is so we don't get both normal output AND debugging output, AND so we get the proper log calling file & line number
    """
    @functools.wraps(func)
    def wrapper(self, msg, *args, **kwargs):
        if self.logger.getEffectiveLevel() >= logging.INFO:
            return func(self, msg, *args, **kwargs)
        else:            
            formatted_text = Text.from_ansi(self.format(msg, *args, **kwargs)[0])
            caller_frame = inspect.currentframe().f_back
            create_temp_logger(caller_frame, formatted_text, args, kwargs)
            self.log_console_to_file(formatted_text, *args, **kwargs)
    return wrapper


class NXCAdapter(logging.LoggerAdapter):
    def __init__(self, extra=None):
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(
                console=nxc_console,
                rich_tracebacks=True,
                tracebacks_show_locals=False
            )],
        )
        self.logger = logging.getLogger("nxc")
        self.extra = extra
        self.output_file = None
        
        logging.getLogger("impacket").disabled = True
        logging.getLogger("pypykatz").disabled = True
        logging.getLogger("minidump").disabled = True
        logging.getLogger("lsassy").disabled = True
        logging.getLogger("dploot").disabled = True
        logging.getLogger("neo4j").setLevel(logging.ERROR)

    def format(self, msg, *args, **kwargs):  # noqa: A003
        """Format msg for output

        This is used instead of process() since process() applies to _all_ messages, including debug calls
        """
        if self.extra is None:
            return f"{msg}", kwargs

        if "module_name" in self.extra and len(self.extra["module_name"]) > 11:
            self.extra["module_name"] = self.extra["module_name"][:8] + "..."

        # If the logger is being called when hooking the 'options' module function
        if len(self.extra) == 1 and ("module_name" in self.extra):
            return (f"{colored(self.extra['module_name'], 'cyan', attrs=['bold']):<64} {msg}", kwargs)

        # If the logger is being called from nxcServer
        if len(self.extra) == 2 and ("module_name" in self.extra) and ("host" in self.extra):
            return (f"{colored(self.extra['module_name'], 'cyan', attrs=['bold']):<24} {self.extra['host']:<39} {msg}", kwargs)

        # If the logger is being called from a protocol
        module_name = colored(self.extra["module_name"], "cyan", attrs=["bold"]) if "module_name" in self.extra else colored(self.extra["protocol"], "blue", attrs=["bold"])

        return (f"{module_name:<24} {self.extra['host']:<15} {self.extra['port']:<6} {self.extra['hostname'] if self.extra['hostname'] else 'NONE':<16} {msg}", kwargs)

    @no_debug
    def display(self, msg, *args, **kwargs):
        """Display text to console, formatted for nxc"""
        msg, kwargs = self.format(f"{colored('[*]', 'blue', attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        nxc_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    @no_debug
    def success(self, msg, color="green", *args, **kwargs):
        """Prints some sort of success to the user"""
        msg, kwargs = self.format(f"{colored('[+]', color, attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        nxc_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    @no_debug
    def highlight(self, msg, *args, **kwargs):
        """Prints a completely yellow highlighted message to the user"""
        msg, kwargs = self.format(f"{colored(msg, 'yellow', attrs=['bold'])}", kwargs)
        text = Text.from_ansi(msg)
        nxc_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    @no_debug
    def fail(self, msg, color="red", *args, **kwargs):
        """Prints a failure (may or may not be an error) - e.g. login creds didn't work"""
        msg, kwargs = self.format(f"{colored('[-]', color, attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        nxc_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def log_console_to_file(self, text, *args, **kwargs):
        """Log the console output to a file

        If debug or info logging is not enabled, we still want display/success/fail logged to the file specified,
        so we create a custom LogRecord and pass it to all the additional handlers (which will be all the file handlers)
        """
        if self.logger.getEffectiveLevel() >= logging.INFO and len(self.logger.handlers):  # will be 0 if it's just the console output, so only do this if we actually have file loggers
            try:
                for handler in self.logger.handlers:
                    handler.handle(LogRecord("nxc", 20, "", kwargs, msg=text, args=args, exc_info=None))
            except Exception as e:
                self.logger.fail(f"Issue while trying to custom print handler: {e}")

    def add_file_log(self, log_file=None):
        file_formatter = TermEscapeCodeFormatter("%(asctime)s - %(levelname)s - %(message)s")
        output_file = self.init_log_file() if log_file is None else log_file
        file_creation = False

        if not os.path.isfile(output_file):
            open(output_file, "x")  # noqa: SIM115
            file_creation = True

        file_handler = RotatingFileHandler(output_file, maxBytes=100000)

        with file_handler._open() as f:
            if file_creation:
                f.write(f"[{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}]> {' '.join(sys.argv)}\n\n")
            else:
                f.write(f"\n[{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}]> {' '.join(sys.argv)}\n\n")

        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        self.logger.debug(f"Added file handler: {file_handler}")

    @staticmethod
    def init_log_file():
        newpath = os.path.expanduser("~/.nxc") + "/logs/" + datetime.now().strftime("%Y-%m-%d")
        if not os.path.exists(newpath):
            os.makedirs(newpath)
        return os.path.join(
            os.path.expanduser("~/.nxc"),
            "logs",
            datetime.now().strftime("%Y-%m-%d"),
            f"log_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.log",
        )
    

class TermEscapeCodeFormatter(logging.Formatter):
    """A class to strip the escape codes for logging to files"""

    def __init__(self, fmt=None, datefmt=None, style="%", validate=True):
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record):  # noqa: A003
        escape_re = re.compile(r"\x1b\[[0-9;]*m")
        record.msg = re.sub(escape_re, "", str(record.msg))
        return super().format(record)


# initialize the logger for all of nxc - this is imported everywhere
nxc_logger = NXCAdapter()
