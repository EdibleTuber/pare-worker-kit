"""The one string a worker and the daemon must agree on.

It lives here rather than in agent_core because the direction matters: this
is the SERVER side of a worker, and agent_core's stated boundary is the
CLIENT side -- transport, enforcement, lifecycle. Putting the serving helper
in agent_core would mean the machine being protected from the worker also
ships the code the worker runs.

agent_core does NOT import this. It states the same literal in its own
`agent_core.workers.risk`, because the daemon and a worker are installed
separately on different machines and never share a Python environment --
a shared constant is not available to them, and a re-export would be a
cross-import in the direction this split exists to prevent.

So there are deliberately TWO definitions, kept honest by a guard test on
each side that asserts the other's matches when it is installed. An
earlier version of this docstring claimed a re-export and "exactly one
definition", which was false and made the guard tests look redundant.
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
