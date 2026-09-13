"""Worker-side request logging for networked transports.

Over stdio the daemon spawned the worker and holds its pipe, so the daemon's
own audit log already is a total record of what the worker did. Over HTTP
that stops being true: anything that can route to the port can call a tool
directly, and the daemon never sees it. This is the log that closes that gap
-- and because it is the worker's OWN record, it has to keep working when
the daemon is absent, dishonest, or simply never involved.
"""
from __future__ import annotations

import json
import os
import re

import pytest
from mcp import types

from pare_worker_kit import run_worker
from pare_worker_kit.serve import (_install_request_log, _peer_address,
                                   _record_request, _sanitize_tool_name)


def _request_lines(log_path):
    """The install hook writes a header line (event=log_started) with no
    args_sha256 field; most assertions here care about the per-call lines
    that follow it, not the header."""
    return [l for l in log_path.read_text().splitlines() if "args_sha256=" in l]


class _FakeSettings:
    def __init__(self):
        self.host = None
        self.port = None
        self.transport_security = None
        self.stateless_http = False


class _Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class _FakeRequestContext:
    """Stands in for mcp.shared.context.RequestContext. `request` is the
    Starlette Request over HTTP transports, and is None over stdio -- the
    kit never even reaches for it there, but the fake mirrors it anyway."""

    def __init__(self, request):
        self.request = request


class _FakeLowServer:
    """Stands in for the low-level mcp.server.lowlevel.server.Server that
    `server._mcp_server` is. `request_handlers` is the real dispatch dict
    shape: a plain dict keyed by request type, read at call time -- which is
    exactly the property the hook depends on."""

    def __init__(self, call_tool_handler, request=None, context_raises=None):
        self.request_handlers = {types.CallToolRequest: call_tool_handler}
        self._request = request
        self._context_raises = context_raises

    @property
    def request_context(self):
        if self._context_raises is not None:
            raise self._context_raises
        return _FakeRequestContext(self._request)


class _FakeServer:
    """Stands in for the FastMCP instance run_worker receives: has
    `.settings` for the host/port branch and `._mcp_server` for the
    dispatch-table branch the logging hook patches."""

    def __init__(self, call_tool_handler, request=None):
        self.settings = _FakeSettings()
        self._mcp_server = _FakeLowServer(call_tool_handler, request=request)
        self.ran = None

    def run(self, transport="stdio", mount_path=None):
        self.ran = {"transport": transport}


def _call_tool_request(name, arguments):
    return types.CallToolRequest(
        params=types.CallToolRequestParams(name=name, arguments=arguments))


def _http_env(port, log_path):
    return {"AGENT_WORKER_TRANSPORT": "http", "AGENT_WORKER_PORT": str(port),
            "AGENT_WORKER_REQUEST_LOG": str(log_path)}


# --- the call is recorded --------------------------------------------------


async def test_a_call_is_recorded_with_peer_tool_and_timestamp(tmp_path):
    log_path = tmp_path / "requests.log"
    calls = []

    async def original(req):
        calls.append(req)
        return types.ServerResult(types.CallToolResult(content=[], isError=False))

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("100.64.0.7", 53214))
    run_worker(server, env=_http_env(9200, log_path))

    req = _call_tool_request("console_send", {"line": "boot"})
    result = await server._mcp_server.request_handlers[types.CallToolRequest](req)

    assert calls == [req], "the original handler must still run"
    assert isinstance(result, types.ServerResult)

    lines = _request_lines(log_path)
    assert len(lines) == 1
    line = lines[0]
    assert "peer=100.64.0.7:53214" in line
    assert "tool=console_send" in line

    ts = line.split(" ", 1)[0]
    from datetime import datetime
    datetime.fromisoformat(ts)  # raises if it is not a real timestamp


class _FakeRequestContextRequestStub:
    """The Starlette Request has a `.client` with `.host`/`.port`; nothing
    else about it is used, so nothing else is faked."""

    def __init__(self, host, port):
        self.client = _Client(host, port)


async def test_arguments_are_hashed_never_recorded_verbatim(tmp_path):
    """A console `send` payload can carry credentials typed at a target's
    login prompt. The secret value must not appear anywhere in the log --
    only a hash that answers 'was this the same call'."""
    log_path = tmp_path / "requests.log"
    secret = "hunter2-do-not-log-me"

    async def original(req):
        return types.ServerResult(types.CallToolResult(content=[], isError=False))

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 4000))
    run_worker(server, env=_http_env(9201, log_path))

    req = _call_tool_request("console_send", {"password": secret})
    await server._mcp_server.request_handlers[types.CallToolRequest](req)

    raw = log_path.read_bytes()
    assert secret.encode() not in raw
    assert re.search(rb"args_sha256=[0-9a-f]{64}", raw), (
        "a hash must still be recorded -- just not the value it is a hash of")


async def test_the_hash_is_salted_not_a_bare_sha256(tmp_path):
    """A bare, unsalted sha256 lets one table -- computed once, offline,
    against likely short arguments -- be reused against every worker's log
    forever. The salt does not make this file a safe place for a secret
    (see the docstring on `_record_request`), but the logged digest must at
    least not equal the value an attacker without the salt would precompute."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    run_worker(server, env=_http_env(9213, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    await handler(_call_tool_request("console_send", {"password": "hunter2"}))

    bare_digest = __import__("hashlib").sha256(
        json.dumps({"password": "hunter2"}, sort_keys=True).encode()).hexdigest()
    assert f"args_sha256={bare_digest}" not in log_path.read_text()


def test_the_header_line_declares_the_process_salt(tmp_path):
    """The salt is logged once, up front -- not to protect it (anyone who
    can read the log can read this line), but so a reader can see that
    different processes (and restarts) used different salts and therefore
    do not share one precomputed table."""
    log_path = tmp_path / "requests.log"
    server = _FakeServer(lambda req: None)

    _install_request_log(server, env={"AGENT_WORKER_REQUEST_LOG": str(log_path)},
                         env_prefix="AGENT_WORKER_")

    header = log_path.read_text().splitlines()[0]
    assert "event=log_started" in header
    assert re.search(r"salt=[0-9a-f]{32}", header)


async def test_the_hash_is_stable_across_argument_key_order(tmp_path):
    """The same logical call must hash the same way regardless of which
    order a particular client happened to serialise its keys in."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return types.ServerResult(types.CallToolResult(content=[], isError=False))

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 4000))
    run_worker(server, env=_http_env(9202, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    await handler(_call_tool_request("flash_write", {"a": 1, "b": 2}))
    await handler(_call_tool_request("flash_write", {"b": 2, "a": 1}))

    lines = _request_lines(log_path)
    digests = [re.search(r"args_sha256=(\S+)", line).group(1) for line in lines]
    assert digests[0] == digests[1]


# --- an attacker-controlled tool name cannot forge the log -----------------
#
# CallToolRequestParams.name is a bare str with no pattern constraint, and
# this module's own threat model is "anything that can route to the port" --
# so name is exactly as untrusted as the connection that sent it. These
# guard the log format itself, independent of the hashing tests above.


async def test_a_newline_in_the_tool_name_cannot_forge_a_second_line(tmp_path):
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    run_worker(server, env=_http_env(9214, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    hostile = "console_send\nFORGED peer=9.9.9.9 tool=steal_flash args_sha256=deadbeef"
    result = await handler(_call_tool_request(hostile, {}))

    assert result == "ok", "the real tool call must still complete"
    lines = _request_lines(log_path)
    assert len(lines) == 1, (
        "a newline inside the tool name must not create a second log line")
    assert "\\x0a" in lines[0], "the newline must be escaped, not silently dropped"


async def test_a_tool_name_cannot_inject_a_fake_field(tmp_path):
    """A name containing the format's own separator text must not be able
    to make the line APPEAR to carry a different peer, tool, or hash than
    the ones this process actually recorded."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    run_worker(server, env=_http_env(9215, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    hostile = "x peer=9.9.9.9 tool=steal_flash args_sha256=deadbeef"
    await handler(_call_tool_request(hostile, {}))

    line = _request_lines(log_path)[0]
    assert line.count(" peer=") == 1
    assert line.count(" tool=") == 1
    assert line.count(" args_sha256=") == 1
    assert "peer=10.0.0.1:1" in line
    assert "peer=9.9.9.9" not in line


def test_sanitize_leaves_ordinary_identifiers_alone():
    """The escaping must not make ordinary, well-behaved tool names ugly --
    every real tool name in this system is exactly this shape."""
    assert _sanitize_tool_name("console_send") == "console_send"
    assert _sanitize_tool_name("flash-write.v2") == "flash-write.v2"


# --- a logging failure never fails the request ------------------------------


async def test_a_logging_failure_does_not_propagate(tmp_path):
    """A full disk must not take a hardware bench offline. Point the log at
    a path whose parent is a plain FILE, so os.makedirs is guaranteed to
    fail with an error that has nothing to do with permissions bits or
    platform quirks."""
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("occupied")
    log_path = blocked / "sub" / "requests.log"

    async def original(req):
        return "the tool's own result"

    server = _FakeServer(original, request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    run_worker(server, env=_http_env(9203, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    result = await handler(_call_tool_request("console_send", {"x": 1}))

    assert result == "the tool's own result", (
        "the request must still complete even though its log line could not "
        "be written")
    assert not blocked.is_dir(), "the failure must be the one we engineered"


async def test_a_peer_lookup_failure_does_not_propagate(tmp_path):
    """request_context can raise LookupError outside of an active request.
    That must degrade to 'unknown', never abort the call."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original)
    server._mcp_server = _FakeLowServer(original, context_raises=LookupError())
    run_worker(server, env=_http_env(9204, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    result = await handler(_call_tool_request("console_send", {}))

    assert result == "ok"
    assert "peer=unknown" in log_path.read_text()


def test_record_request_swallows_every_exception_directly():
    """Unit-level guarantee behind the invariant above: _record_request
    itself never raises, independent of how it is wired in."""
    class _ExplodingLowServer:
        @property
        def request_context(self):
            raise RuntimeError("boom")

    req = _call_tool_request("console_send", {"a": 1})
    _record_request(_ExplodingLowServer(), "/definitely/not/writable/x.log", req)


# --- stdio is unaffected -----------------------------------------------------


def test_stdio_never_installs_the_hook(tmp_path):
    """The gap this closes exists only for networked transports; a stdio
    worker is already covered end-to-end by the daemon's own log, and must
    come out of run_worker with its dispatch table untouched."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return None

    server = _FakeServer(original)
    handlers = server._mcp_server.request_handlers
    before = handlers[types.CallToolRequest]

    run_worker(server, env={"AGENT_WORKER_REQUEST_LOG": str(log_path)})

    assert server.ran == {"transport": "stdio"}
    assert handlers[types.CallToolRequest] is before, (
        "stdio must not be wrapped -- this hook is HTTP-only")
    assert not log_path.exists(), "stdio must record nothing"


async def test_stdio_records_nothing_even_if_a_tool_is_called_directly(tmp_path):
    """Belt and suspenders on the invariant above: even if something called
    the (unwrapped) handler directly, no log file appears, because stdio
    never installs the hook in the first place."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original)
    run_worker(server, env={"AGENT_WORKER_REQUEST_LOG": str(log_path)})

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    result = await handler(_call_tool_request("console_send", {"a": 1}))

    assert result == "ok"
    assert not log_path.exists()


# --- installation itself is defensive ---------------------------------------


def test_install_is_a_noop_when_there_is_no_low_level_server(capsys):
    """The standalone `fastmcp` package's FastMCP has no `_mcp_server`.
    Installation must not assume the mcp SDK's internals are present -- and
    must say so loudly rather than quietly stop auditing."""
    class _StandaloneServer:
        pass

    _install_request_log(_StandaloneServer(), env={}, env_prefix="AGENT_WORKER_")
    err = capsys.readouterr().err
    assert "DISABLED" in err
    assert "_mcp_server" in err


def test_install_is_a_noop_when_there_is_no_request_handlers_dict(capsys):
    class _NoHandlers:
        pass

    class _Bare:
        _mcp_server = _NoHandlers()

    _install_request_log(_Bare(), env={}, env_prefix="AGENT_WORKER_")
    err = capsys.readouterr().err
    assert "DISABLED" in err
    assert "request_handlers" in err


def test_install_is_a_noop_when_call_tool_is_not_registered(capsys):
    server = _FakeServer(lambda req: None)
    server._mcp_server.request_handlers.clear()
    _install_request_log(server, env={}, env_prefix="AGENT_WORKER_")
    assert types.CallToolRequest not in server._mcp_server.request_handlers
    err = capsys.readouterr().err
    assert "DISABLED" in err
    assert "CallToolRequest" in err


async def test_install_against_a_real_fastmcp_instance(tmp_path):
    """Every other test in this file drives the hook through hand-rolled
    fakes that mirror the hook's OWN assumptions about the mcp SDK's shape.
    mcp is pinned to a range (>=1.27.0,<2), not one version -- a routine
    upgrade inside that range could rename or restructure `_mcp_server`,
    `request_handlers`, or `CallToolRequest`, and every fake above would
    keep passing while production silently stopped auditing. This is the
    one test built against the REAL mcp.server.fastmcp.FastMCP that would
    notice."""
    from mcp.server.fastmcp import FastMCP

    real_server = FastMCP("probe")

    @real_server.tool()
    def echo(secret: str) -> str:
        return "ok:" + secret

    log_path = tmp_path / "requests.log"
    _install_request_log(real_server,
                         env={"AGENT_WORKER_REQUEST_LOG": str(log_path)},
                         env_prefix="AGENT_WORKER_")

    handler = real_server._mcp_server.request_handlers[types.CallToolRequest]
    req = _call_tool_request("echo", {"secret": "topsecret"})
    result = await handler(req)

    assert result.root.content[0].text == "ok:topsecret"
    text = log_path.read_text()
    assert "tool=echo" in text
    assert "topsecret" not in text


def test_default_log_path_honours_xdg_state_home(monkeypatch, tmp_path):
    from pare_worker_kit.serve import _default_request_log_path

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    path = _default_request_log_path()
    assert path == os.path.join(str(tmp_path), "pare-worker", "requests.log")


def test_peer_address_falls_back_to_unknown_with_no_client():
    server = _FakeLowServer(lambda req: None, request=object())
    assert _peer_address(server) == "unknown"
