# main.py

import sys
from rich.console import Console
from cli import run

console = Console()

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[bold red] Dibatalkan pengguna — keluar program.[/bold red]")
        sys.exit(1)
