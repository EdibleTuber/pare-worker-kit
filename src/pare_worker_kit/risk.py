"""The one string a worker and the daemon must agree on.

It lives here rather than in agent_core because the direction matters: this
is the SERVER side of a worker, and agent_core's stated boundary is the
CLIENT side -- transport, enforcement, lifecycle. Putting the serving helper
in agent_core would mean the machine being protected from the worker also
ships the code the worker runs.

agent_core re-exports this name, so there is still exactly one definition.
"""

RISK_TIER_META_KEY = "agent_core/risk_tier"
"""The _meta key a worker uses to advertise a tool's risk tier over the wire.

The daemon treats a wire-advertised tier as ESCALATE-ONLY: it can raise a
tool above the floor in workers.yaml, never lower it. So a worker that lies
about this can only make itself more restricted, and a worker that omits it
gets its declared floor. Keep the string stable; it is protocol.
"""

VALID_RISK_TIERS = ("low", "medium", "high", "critical")
"""Lowercase, exactly. The daemon's conformance check rejects 'LOW'."""
