"""Compatibility facade for the former `transactions` module.

This file remains only so older imports still resolve. The real low-level transaction and
instruction code now lives in `protocol.py`.
"""

from .protocol import *  # noqa: F401,F403
