"""The server half of a PARE worker.

Deliberately small, and depends on `mcp` alone: a worker runs on whatever
machine owns its hardware, which may be a Raspberry Pi.
"""
from pare_worker_kit.artifacts import (PRODUCES_ARTIFACT, PRODUCES_META_KEY,
                                       PRODUCES_RESULT, VALID_PRODUCES)
from pare_worker_kit.risk import RISK_TIER_META_KEY, VALID_RISK_TIERS
from pare_worker_kit.serve import (WorkerServeError, resolve_bind_address,
                                   run_worker, stamp_version)

__all__ = ["PRODUCES_ARTIFACT", "PRODUCES_META_KEY", "PRODUCES_RESULT",
           "VALID_PRODUCES", "RISK_TIER_META_KEY", "VALID_RISK_TIERS",
           "run_worker", "resolve_bind_address", "stamp_version",
           "WorkerServeError"]
__version__ = "0.1.2"
