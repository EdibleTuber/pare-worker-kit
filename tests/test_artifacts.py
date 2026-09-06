import pytest

from pare_worker_kit import (PRODUCES_ARTIFACT, PRODUCES_META_KEY,
                             PRODUCES_RESULT, VALID_PRODUCES)


def test_the_meta_key_is_stable_protocol():
    """agent_core states this same literal independently; a guard test in each
    suite keeps them equal. Changing it is a wire-breaking change."""
    assert PRODUCES_META_KEY == "agent_core/produces"


def test_result_is_the_default_value():
    """A tool that says nothing produces a result. Only an explicit
    declaration opts into the artifact path."""
    assert PRODUCES_RESULT == "result"
    assert PRODUCES_ARTIFACT == "artifact"
    assert VALID_PRODUCES == ("result", "artifact")


def test_it_agrees_with_agent_cores():
    ac = pytest.importorskip(
        "agent_core.workers.artifacts",
        reason="agent_core is not installed here; the daemon-side half of "
               "this check runs in agent_core's own suite")
    assert ac.PRODUCES_META_KEY == PRODUCES_META_KEY
    assert ac.VALID_PRODUCES == VALID_PRODUCES
