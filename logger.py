import os
import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install

# ignore errors from these libs
import tomlkit, websockets

console = Console()

_print = print  # save python's print.

print = console.print  # raw print


def setup_logging():
    FORMAT = "%(message)s"
    logging_handler = RichHandler(
        level=os.environ.get("LOGLEVEL", "INFO"),
        console=console,
        rich_tracebacks=True,
        tracebacks_suppress=[tomlkit, websockets]
    )

    logging.basicConfig(
        level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[logging_handler]
    )

    install(
        console = console
    )
