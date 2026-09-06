"""What a tool produces, and where a worker is allowed to write it.

The daemon routes on this declaration rather than on the model's choice of
tool: a tool marked `artifact` returns a DESCRIPTOR of a file it wrote, never
the file's contents. Without it, a two-gigabyte firmware dump would cross the
network as one tool result.
"""

PRODUCES_META_KEY = "agent_core/produces"
"""The _meta key a tool uses to declare what it returns.

Stated here AND in agent_core, with a guard test on each side, because the
daemon and the worker are separately installed packages that never share a
Python environment -- so a shared import could not guarantee agreement across
the wire any better than two literals can.
"""

PRODUCES_RESULT = "result"
PRODUCES_ARTIFACT = "artifact"

VALID_PRODUCES = (PRODUCES_RESULT, PRODUCES_ARTIFACT)
"""Absent means `result`. An unrecognised value is a conformance failure at
build time, not a silent default -- the same choice the risk tier makes, and
copying the mechanism without copying that choice would lose the property."""
