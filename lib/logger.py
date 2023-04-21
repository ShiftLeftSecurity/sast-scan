import logging
import os

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

custom_theme = Theme({"info": "cyan", "warning": "purple4", "danger": "bold red"})
color_system = "256"
if os.getenv("SHIFTLEFT_ACCESS_TOKEN") or os.getenv("SHIFTLEFT_APP"):
    color_system = "auto"
console = Console(
    log_time=False,
    log_path=False,
    theme=custom_theme,
    width=140,
    color_system=color_system,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=console, markup=True, show_path=False, enable_link_path=False
        )
    ],
)
LOG = logging.getLogger(__name__)

# Set logging level
if os.getenv("SCAN_DEBUG_MODE") == "debug":
    LOG.setLevel(logging.DEBUG)

DEBUG = logging.DEBUG
