"""The server half of a PARE worker.

Deliberately small, and depends on `mcp` alone: a worker runs on whatever
machine owns its hardware, which may be a Raspberry Pi.
"""
from pare_worker_kit.risk import RISK_TIER_META_KEY, VALID_RISK_TIERS
from pare_worker_kit.serve import (WorkerServeError, resolve_bind_address,
                                   run_worker)

__all__ = ["RISK_TIER_META_KEY", "VALID_RISK_TIERS", "run_worker",
           "resolve_bind_address", "WorkerServeError"]
__version__ = "0.1.0"
