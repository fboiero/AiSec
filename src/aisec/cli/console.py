"""Rich console singleton and theming."""

from rich.console import Console
from rich.theme import Theme

aisec_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "agent": "bold magenta",
    "finding": "bold yellow",
})

console = Console(theme=aisec_theme)
