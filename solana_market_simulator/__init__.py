"""Top-level package export for the simulator.

This file keeps the package import surface small and currently exposes the demo `main()`
entrypoint. Most implementation code lives in the submodules next to this file.
"""

from .app import main

__all__ = ["main"]
