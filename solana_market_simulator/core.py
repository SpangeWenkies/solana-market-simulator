"""Compatibility facade for the former mixed `core` module.

Internal code should import from:
- `domain.py` for market/player/validator definitions and intent compilation
- `policies.py` for state-driven policy logic
- `simulation.py` for the multi-slot simulation loop
"""

from .domain import *  # noqa: F401,F403
from .policies import *  # noqa: F401,F403
from .simulation import run_simulation
