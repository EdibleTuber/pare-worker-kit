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
                                   _record_request)


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

    lines = log_path.read_text().splitlines()
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

    expected_digest = __import__("hashlib").sha256(
        json.dumps({"password": secret}, sort_keys=True).encode()).hexdigest()
    assert f"args_sha256={expected_digest}" in raw.decode()


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

    lines = log_path.read_text().splitlines()
    digests = [re.search(r"args_sha256=(\S+)", line).group(1) for line in lines]
    assert digests[0] == digests[1]


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


def test_install_is_a_noop_when_there_is_no_low_level_server():
    """The standalone `fastmcp` package's FastMCP has no `_mcp_server`.
    Installation must not assume the mcp SDK's internals are present."""
    class _StandaloneServer:
        pass

    _install_request_log(_StandaloneServer(), env={}, env_prefix="AGENT_WORKER_")
    # No exception is the assertion.


def test_install_is_a_noop_when_call_tool_is_not_registered():
    server = _FakeServer(lambda req: None)
    server._mcp_server.request_handlers.clear()
    _install_request_log(server, env={}, env_prefix="AGENT_WORKER_")
    assert types.CallToolRequest not in server._mcp_server.request_handlers


def test_default_log_path_honours_xdg_state_home(monkeypatch, tmp_path):
    from pare_worker_kit.serve import _default_request_log_path

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    path = _default_request_log_path()
    assert path == os.path.join(str(tmp_path), "pare-worker", "requests.log")


def test_peer_address_falls_back_to_unknown_with_no_client():
    server = _FakeLowServer(lambda req: None, request=object())
    assert _peer_address(server) == "unknown"
