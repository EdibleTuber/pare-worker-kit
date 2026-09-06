"""run_worker's job is to refuse bad launches before anything binds."""
import ipaddress
import socket

import pytest

from pare_worker_kit import (RISK_TIER_META_KEY, WorkerServeError, stamp_version,
                             resolve_bind_address, run_worker)


class _FakeSettings:
    """Stands in for mcp.server.fastmcp.server.Settings."""
    def __init__(self, stateless_http=False):
        self.host = None
        self.port = None
        self.transport_security = None
        self.stateless_http = stateless_http


class _BundledServer:
    """mcp.server.fastmcp.FastMCP shape: run() takes no host/port."""
    def __init__(self, stateless_http=False):
        self.settings = _FakeSettings(stateless_http)
        self.ran = None

    def run(self, transport="stdio", mount_path=None):
        self.ran = {"transport": transport}


class _StandaloneServer:
    """The standalone fastmcp package's shape: no settings, kwargs on run()."""
    def __init__(self):
        self.ran = None

    def run(self, transport=None, **kwargs):
        self.ran = {"transport": transport, **kwargs}


# --- the wildcard refusal ------------------------------------------------

def _kernel_binds_as_wildcard(spelling: str) -> str | None:
    """What the KERNEL does with this spelling, not what ipaddress thinks.

    This is the ground truth the test needs. ipaddress.ip_address REJECTS
    '0', '0x0', '00.0.0.0' and '0000' -- Python dropped those forms in 3.9.5 --
    while the C resolver still turns every one of them into 0.0.0.0 and the
    kernel binds it. A test that asked ipaddress would agree with the buggy
    implementation it is supposed to catch.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.bind((spelling, 0))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return None


@pytest.mark.parametrize("spelling", ["0.0.0.0", "0", "0x0", "00.0.0.0", "0000",
                                      "0.0.0.0.", "::", "::0",
                                      "0:0:0:0:0:0:0:0"])
def test_no_spelling_of_the_wildcard_gets_through(spelling):
    """The bind address is the only access control this worker has, so the
    question is not 'does it reject the string 0.0.0.0' but 'can anything an
    operator might type end up bound to every interface'.

    Measured on this host: '0', '0x0', '00.0.0.0' and '0000' all bind
    0.0.0.0, and '::' binds the v6 wildcard which, with net.ipv6.bindv6only=0
    (the Linux default), accepts IPv4 too. Only '0.0.0.0.' -- with the
    trailing dot -- does not bind at all.
    """
    bound = _kernel_binds_as_wildcard(spelling)
    with pytest.raises(WorkerServeError) as e:
        resolve_bind_address(spelling)
    if bound is not None and ipaddress.ip_address(bound).is_unspecified:
        # The kernel WOULD have exposed every interface: this must be
        # refused as a wildcard, by name, so the operator knows why.
        assert "wildcard" in str(e.value), (spelling, bound, str(e.value))
    else:
        # Not bindable at all; any refusal is correct, but it must still be
        # a refusal rather than something that reaches uvicorn.
        assert str(e.value)


def test_the_wildcard_check_does_not_rely_on_ipaddress_alone():
    """The load-bearing half. Guarding this so a later 'simplification' to a
    single ipaddress.ip_address() call fails loudly instead of silently
    reopening four spellings."""
    for spelling in ("0", "0x0", "00.0.0.0", "0000"):
        with pytest.raises(ValueError):
            ipaddress.ip_address(spelling)        # Python cannot parse it...
        with pytest.raises(WorkerServeError, match="wildcard"):
            resolve_bind_address(spelling)        # ...but we still refuse it


def test_the_refusal_tells_the_operator_what_to_do_instead():
    """An operator at a bench who is told only 'no' reaches for the thing
    that works. Name the two ways out."""
    with pytest.raises(WorkerServeError) as e:
        resolve_bind_address("0.0.0.0")
    text = str(e.value)
    assert "tailscale0" in text and "AGENT_WORKER_HOST" in text


def test_loopback_and_real_addresses_are_accepted():
    assert resolve_bind_address("127.0.0.1") == "127.0.0.1"
    assert resolve_bind_address("100.64.0.1") == "100.64.0.1"
    assert resolve_bind_address("::1") == "::1"


def test_a_name_is_resolved_here_not_at_bind_time():
    """What we validate must be what we bind, or the check has a gap."""
    assert resolve_bind_address("localhost") in ("127.0.0.1", "::1")


def test_an_interface_name_resolves_to_its_address():
    """The path that makes the wildcard refusal defensible rather than
    merely obstructive."""
    lo = resolve_bind_address("lo")
    assert lo == "127.0.0.1"


def test_an_unknown_host_is_a_clear_error_not_a_wildcard():
    with pytest.raises(WorkerServeError, match="neither an IP address"):
        resolve_bind_address("no-such-host-anywhere.invalid")


def test_empty_host_is_refused():
    with pytest.raises(WorkerServeError):
        resolve_bind_address("   ")


# --- transport selection --------------------------------------------------

def test_stdio_is_the_default_and_needs_no_port():
    server = _BundledServer()
    run_worker(server, env={})
    assert server.ran == {"transport": "stdio"}


@pytest.mark.parametrize("spelling", ["http", "streamable_http", "streamable-http",
                                      "HTTP", " http "])
def test_both_spellings_of_the_http_transport_are_accepted(spelling):
    """WorkerSpec.transport is 'streamable_http' (underscore) and FastMCP.run
    wants 'streamable-http' (hyphen). An operator should not have to
    remember which side of the wire they are writing for."""
    server = _BundledServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": spelling,
                            "AGENT_WORKER_PORT": "9101"})
    assert server.ran["transport"] == "streamable-http"


def test_an_unknown_transport_names_the_valid_ones():
    with pytest.raises(WorkerServeError, match="unknown transport"):
        run_worker(_BundledServer(), env={"AGENT_WORKER_TRANSPORT": "sse"})


def test_http_without_a_port_is_refused_here_not_inside_uvicorn():
    """There is no default port on purpose: two workers on one laptop would
    both take it and the second would die with a socket error rather than a
    configuration one."""
    with pytest.raises(WorkerServeError, match="required when serving over http"):
        run_worker(_BundledServer(), env={"AGENT_WORKER_TRANSPORT": "http"})


@pytest.mark.parametrize("bad", ["nine", "0", "65536", "-1"])
def test_an_unusable_port_is_refused(bad):
    with pytest.raises(WorkerServeError):
        run_worker(_BundledServer(), env={"AGENT_WORKER_TRANSPORT": "http",
                                          "AGENT_WORKER_PORT": bad})


def test_http_defaults_to_loopback_when_no_host_is_given():
    server = _BundledServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": "http",
                            "AGENT_WORKER_PORT": "9101"})
    assert (server.settings.host, server.settings.port) == ("127.0.0.1", 9101)


# --- the two FastMCP classes ---------------------------------------------

def test_the_bundled_class_gets_host_and_port_through_settings():
    """mcp.server.fastmcp.FastMCP.run() accepts neither as a kwarg; passing
    them would be a TypeError, and setting them nowhere would silently serve
    on the SDK default."""
    server = _BundledServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": "http",
                            "AGENT_WORKER_HOST": "127.0.0.1",
                            "AGENT_WORKER_PORT": "9107"})
    assert (server.settings.host, server.settings.port) == ("127.0.0.1", 9107)
    assert "host" not in server.ran


def test_the_standalone_class_gets_them_as_kwargs():
    """agent_core's conformance fixture uses the standalone fastmcp package.
    Branching on the object is what stops fixture and production diverging."""
    server = _StandaloneServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": "http",
                            "AGENT_WORKER_HOST": "127.0.0.1",
                            "AGENT_WORKER_PORT": "9108"})
    assert server.ran == {"transport": "streamable-http",
                          "host": "127.0.0.1", "port": 9108}


# --- the session id ------------------------------------------------------

def test_stateless_http_is_refused():
    """Session ids are currently the only thing that surfaces a worker
    restart to the daemon. Without one, a scope: session approval can
    survive onto a different process."""
    server = _BundledServer(stateless_http=True)
    with pytest.raises(WorkerServeError, match="session"):
        run_worker(server, env={"AGENT_WORKER_TRANSPORT": "http",
                                "AGENT_WORKER_PORT": "9101"})


def test_dns_rebinding_protection_is_turned_on():
    """The SDK ships TransportSecurityMiddleware and disables it when no
    settings are passed, which is what FastMCP does."""
    server = _BundledServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": "http",
                            "AGENT_WORKER_HOST": "127.0.0.1",
                            "AGENT_WORKER_PORT": "9109"})
    sec = server.settings.transport_security
    assert sec.enable_dns_rebinding_protection is True
    assert "127.0.0.1:9109" in sec.allowed_hosts


# --- the constant --------------------------------------------------------

def test_the_meta_key_is_the_string_the_daemon_expects():
    """This is protocol. agent_core re-exports this exact name, and a
    conformance test there asserts the same literal."""
    assert RISK_TIER_META_KEY == "agent_core/risk_tier"


def test_the_meta_key_agrees_with_agent_cores():
    """The daemon and the worker are separately installed packages on
    DIFFERENT MACHINES -- the Pi never shares a Python environment with the
    inference server. A shared import could not guarantee agreement across
    that gap any more than two literals can; version skew between two
    installed packages is possible either way. So the string is stated on
    both sides and this test is what enforces it, in whichever environment
    happens to have both.
    """
    agent_core_risk = pytest.importorskip(
        "agent_core.workers.risk",
        reason="agent_core is not installed here; the daemon-side half of "
               "this check runs in agent_core's own suite")
    assert agent_core_risk.RISK_TIER_META_KEY == RISK_TIER_META_KEY


# --- serverInfo.version is provenance, and its default is misleading ------

class _LowServer:
    def __init__(self, name):
        self.name = name
        self.version = None


class _VersionedServer(_BundledServer):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self._mcp_server = _LowServer(name)


def test_the_sdk_default_is_the_problem_being_fixed():
    """Not a hypothetical. mcp.server.fastmcp.FastMCP takes no `version`
    argument, so the low-level Server gets None and the SDK reports ITS OWN
    version. Measured against a real worker: a freshly built pare-static-mcp
    announced serverInfo.version "1.29.1", the mcp library's version."""
    import inspect

    from mcp.server.fastmcp import FastMCP

    assert "version" not in inspect.signature(FastMCP.__init__).parameters
    assert FastMCP("probe")._mcp_server.version is None


def test_stamp_version_uses_installed_package_metadata():
    """Asserts the RELATIONSHIP, not a literal.

    Comparing against the source `__version__` couples this test to a
    reinstall: bumping the version in pyproject.toml makes source and
    installed metadata disagree until `pip install -e .` runs again, so the
    test would fail on the one change it should be indifferent to. What
    stamp_version actually promises is that a worker reports the version of
    the package that is INSTALLED -- which is the value an operator comparing
    two audit rows is looking at.
    """
    from importlib.metadata import version as installed_version

    server = _VersionedServer("pare-worker-kit")
    stamped = stamp_version(server)
    assert stamped == installed_version("pare-worker-kit")
    assert server._mcp_server.version == stamped


def test_an_explicit_version_wins():
    server = _VersionedServer("pare-worker-kit")
    assert stamp_version(server, "9.9.9") == "9.9.9"
    assert server._mcp_server.version == "9.9.9"


def test_an_uninstalled_name_leaves_the_version_alone():
    """A worker run from a source tree with no metadata must still start."""
    server = _VersionedServer("not-a-real-distribution-name-anywhere")
    assert stamp_version(server) is None
    assert server._mcp_server.version is None


def test_a_server_without_a_lowlevel_handle_is_tolerated():
    assert stamp_version(_StandaloneServer()) is None


def test_run_worker_stamps_before_serving():
    """The daemon reads serverInfo at initialize, so it has to be set by the
    time the transport starts -- not left to each worker to remember."""
    from importlib.metadata import version as installed_version

    server = _VersionedServer("pare-worker-kit")
    run_worker(server, env={})
    assert server._mcp_server.version == installed_version("pare-worker-kit")
    assert server.ran == {"transport": "stdio"}
