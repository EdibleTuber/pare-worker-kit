"""The risk-tier list is stated twice; keep the two honest.

`VALID_RISK_TIERS` here and `_WIRE_VALID_TIERS` in
`agent_core/workers/conformance.py` are independent literals, for the same
reason every other shared wire constant is: the daemon and a worker are
installed separately on different machines and never share a Python
environment. The newer `produces` and slug rules were guarded both ways from
the start; this one predates that practice and was left unguarded in both
directions.

Drift here is quiet and bad in a specific way. The daemon's conformance check
asserts an advertised tier is in ITS list. If the kit later gains a tier the
daemon does not know, every worker advertising it fails conformance at build
time with a message about an invalid tier -- and the tier is perfectly valid,
on one side.
"""
from __future__ import annotations

import pytest

from pare_worker_kit import VALID_RISK_TIERS


def test_the_tier_list_agrees_with_agent_cores():
    ac = pytest.importorskip(
        "agent_core.workers.conformance",
        reason="agent_core is not installed here; the daemon-side half of "
               "this check runs in agent_core's own suite")
    assert set(VALID_RISK_TIERS) == set(ac._WIRE_VALID_TIERS)


def test_the_tiers_are_ordered_lowest_to_highest_and_complete():
    """A relationship rather than a literal list, so a legitimate new tier does
    not have to be typed into two repos and a test to be added."""
    assert VALID_RISK_TIERS[0] == "low"
    assert VALID_RISK_TIERS[-1] == "critical"
    assert len(set(VALID_RISK_TIERS)) == len(VALID_RISK_TIERS), "duplicate tier"
