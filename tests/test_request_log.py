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


# --- the peer address is a socket, not a request header ---------------------
#
# uvicorn's Config defaults to proxy_headers=True with
# forwarded_allow_ips="127.0.0.1", and ProxyHeadersMiddleware then rewrites
# scope["client"] from X-Forwarded-For for any connection from that host.
# DEFAULT_HOST here IS 127.0.0.1, and mcp.server.fastmcp builds its
# uvicorn.Config with only app/host/port/log_level -- so before the fix a
# single request header chose the peer= field of its own audit record,
# including choosing the daemon's own address. These tests are about the
# mechanism, not the flag: two of them push a real X-Forwarded-For through
# real uvicorn middleware.


async def _client_seen_by(config, xff=b"9.9.9.9", connected_from="127.0.0.1"):
    """Load `config` the way uvicorn.Server.serve() does and push one HTTP
    scope through the app it produces, returning the scope["client"] the
    application actually sees."""
    seen = {}

    async def app(scope, receive, send):
        seen["client"] = scope.get("client")

    config.app = app
    config.load()
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "POST", "path": "/mcp", "raw_path": b"/mcp",
             "query_string": b"", "root_path": "", "scheme": "http",
             "headers": [(b"x-forwarded-for", xff)],
             "client": (connected_from, 53214), "server": ("127.0.0.1", 9300)}

    async def receive():                                   # pragma: no cover
        return {"type": "http.disconnect"}

    async def send(message):                               # pragma: no cover
        pass

    await config.loaded_app(scope, receive, send)
    return seen["client"]


class _UvicornBuildingServer:
    """A FastMCP stand-in that does what mcp.server.fastmcp actually does at
    run() time: build a uvicorn.Config with app/host/port/log_level and
    nothing else. The Config it built is kept so a test can inspect what
    this kit's serving path did to it."""

    def __init__(self):
        self.settings = _FakeSettings()
        self._mcp_server = _FakeLowServer(_noop_handler)
        self.config = None
        self.ran = None

    def run(self, transport="stdio", mount_path=None, **kwargs):
        import uvicorn

        async def app(scope, receive, send):               # pragma: no cover
            pass

        self.ran = {"transport": transport}
        self.config = uvicorn.Config(app, host=self.settings.host or "127.0.0.1",
                                     port=self.settings.port or 9300,
                                     log_level="warning")


async def _noop_handler(req):                              # pragma: no cover
    return "ok"


async def test_a_forwarded_header_cannot_choose_the_peer_over_http(tmp_path):
    """The blocker, end to end through real uvicorn middleware: a request
    carrying X-Forwarded-For from the loopback address this kit binds by
    default must NOT be able to rename itself in the log."""
    server = _UvicornBuildingServer()
    run_worker(server, env=_http_env(9300, tmp_path / "requests.log"))

    assert server.ran == {"transport": "streamable-http"}
    assert server.config.proxy_headers is False
    client = await _client_seen_by(server.config, xff=b"9.9.9.9")
    assert client == ("127.0.0.1", 53214), (
        "scope['client'] must still be the accepted connection; X-Forwarded-For "
        "must not have been able to rewrite it")


async def test_uvicorn_would_otherwise_have_honoured_the_header(tmp_path):
    """The control for the test above. If uvicorn ever stops honouring
    X-Forwarded-For by default, the assertion above would start passing for
    a reason that has nothing to do with this package, and would keep
    passing if the fix were deleted. This test fails in that case, which is
    the signal to go and re-read why the fix is here."""
    import uvicorn

    async def app(scope, receive, send):                   # pragma: no cover
        pass

    unhardened = uvicorn.Config(app, host="127.0.0.1", port=9301,
                                log_level="warning")
    assert unhardened.proxy_headers is True, (
        "uvicorn's own default; the fix exists because of it")
    client = await _client_seen_by(unhardened, xff=b"9.9.9.9")
    assert client == ("9.9.9.9", 0), (
        "this is the attack the kit's serving path has to prevent")


def test_the_forwarded_header_override_does_not_leak_out_of_serving(tmp_path):
    """Patching a third-party class for the life of the process would
    change uvicorn for anything else in the interpreter. The override must
    be gone the moment serving returns."""
    import uvicorn

    before = uvicorn.Config.__init__
    server = _UvicornBuildingServer()
    run_worker(server, env=_http_env(9302, tmp_path / "requests.log"))

    assert uvicorn.Config.__init__ is before

    async def app(scope, receive, send):                   # pragma: no cover
        pass

    assert uvicorn.Config(app, port=9303).proxy_headers is True


def test_stdio_serving_does_not_touch_uvicorn(tmp_path):
    """Invariant 4. The stdio branch returns before any of this, so a
    stdio worker must see uvicorn exactly as it found it -- which also
    rules out an import-time or unconditional patch."""
    server = _UvicornBuildingServer()
    run_worker(server, env={"AGENT_WORKER_TRANSPORT": "stdio",
                            "AGENT_WORKER_REQUEST_LOG": str(tmp_path / "r.log")})

    assert server.ran == {"transport": "stdio"}
    assert server.config.proxy_headers is True, (
        "the stdio path must not have reached the override at all")


async def test_a_forged_peer_cannot_forge_a_log_field(tmp_path):
    """Defence in depth behind proxy_headers=False. A same-host TLS
    terminator, nginx or SSH tunnel legitimately sets X-Forwarded-For, so
    the peer string can still be attacker-influenced in a deployment the
    kit does not control. Whatever it contains, it must not be able to
    fabricate a FIELD -- this is the exact string the live demonstration
    used."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    hostile = "9.9.9.9 tool=console_send args_sha256=0000 FORGED"
    server = _FakeServer(original,
                         request=_FakeRequestContextRequestStub(hostile, 53214))
    run_worker(server, env=_http_env(9304, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    assert await handler(_call_tool_request("flash_write", {})) == "ok"

    line = _request_lines(log_path)[0]
    assert line.count(" peer=") == 1
    assert line.count(" tool=") == 1
    assert line.count(" args_sha256=") == 1
    assert "tool=flash_write" in line, "the real tool must be the one recorded"
    assert "args_sha256=0000 " not in line
    assert " FORGED" not in line


async def test_a_newline_in_the_peer_cannot_forge_a_second_line(tmp_path):
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    hostile = "1.2.3.4\nFORGED peer=9.9.9.9 tool=steal_flash args_sha256=dead"
    server = _FakeServer(original,
                         request=_FakeRequestContextRequestStub(hostile, 1))
    run_worker(server, env=_http_env(9305, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    await handler(_call_tool_request("console_send", {}))

    lines = _request_lines(log_path)
    assert len(lines) == 1
    assert "\\x0a" in lines[0], "the newline must be escaped, not dropped"
    assert "peer=9.9.9.9" not in log_path.read_text()


async def test_an_ipv6_peer_survives_the_escaping_unmangled(tmp_path):
    """Why peer has its own alphabet rather than reusing the tool-name one:
    a peer legitimately contains `:` (the host:port separator and every
    IPv6 literal) and `%` (a zone id), and neither can forge a field, which
    is space-and-`=` delimited. Escaping them would turn every real IPv6
    peer into hex soup for no security gain."""
    log_path = tmp_path / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original,
                         request=_FakeRequestContextRequestStub("fe80::1%eth0", 53214))
    run_worker(server, env=_http_env(9306, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    await handler(_call_tool_request("console_send", {}))

    assert "peer=fe80::1%eth0:53214" in _request_lines(log_path)[0]


def test_the_header_records_whether_the_peer_field_can_be_trusted(tmp_path):
    """A reader opening this file after a bricked target has to know
    whether peer= is evidence or hearsay, and the process that knew is long
    gone by then."""
    log_path = tmp_path / "requests.log"
    server = _UvicornBuildingServer()
    run_worker(server, env=_http_env(9307, log_path))

    header = log_path.read_text().splitlines()[0]
    assert "forwarded_for=ignored" in header


# --- the audit control refuses to start loudly ------------------------------


def _unwritable_log_path(tmp_path):
    """A path whose parent is a plain FILE, so os.makedirs is guaranteed to
    fail with an error that has nothing to do with permissions bits, root,
    or platform quirks."""
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("occupied")
    return blocked / "sub" / "requests.log"


def test_an_unwritable_log_is_announced_at_install(tmp_path, capsys):
    """The install-time write went through `_write_log_line`, which swallows
    everything and returned None, and nothing checked it. So an unwritable
    AGENT_WORKER_REQUEST_LOG, a read-only mount or a full disk produced a
    successful, silent install with a dead audit trail -- exactly the
    failure `_default_request_log_path` names in its own docstring."""
    log_path = _unwritable_log_path(tmp_path)
    server = _FakeServer(_noop_handler)

    run_worker(server, env=_http_env(9308, log_path))

    err = capsys.readouterr().err
    assert "DISABLED" in err
    assert str(log_path) in err, "the message must name the path that failed"
    assert "REQUEST_LOG" in err, "and what to change"


async def test_an_unwritable_log_still_installs_the_hook_and_still_serves(
        tmp_path, capsys):
    """The asymmetry, both halves. Refusing to START is loud; refusing to
    RUN is not on the table -- a full SD card must not be why a hardware
    bench will not come up, and the condition may clear, so the hook goes
    in anyway rather than guaranteeing no records even after a fix."""
    log_path = _unwritable_log_path(tmp_path)

    async def original(req):
        return "the tool's own result"

    server = _FakeServer(original,
                         request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    before = server._mcp_server.request_handlers[types.CallToolRequest]

    run_worker(server, env=_http_env(9309, log_path))

    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    assert handler is not before, "the hook must still be installed"
    assert server.ran == {"transport": "streamable-http"}, "and serving must start"
    assert await handler(_call_tool_request("console_send", {})) == \
        "the tool's own result"


async def test_a_per_request_write_failure_stays_silent(tmp_path, capsys):
    """The other half of the asymmetry, and it is not decoration: making
    the per-request path loud would let anything that can reach the port
    turn one unwritable log into unbounded stderr, and would fire once per
    call for the whole life of a full disk."""
    directory = tmp_path / "state"
    directory.mkdir()
    log_path = directory / "requests.log"

    async def original(req):
        return "ok"

    server = _FakeServer(original,
                         request=_FakeRequestContextRequestStub("10.0.0.1", 1))
    run_worker(server, env=_http_env(9310, log_path))
    assert log_path.exists(), "the install-time write must have succeeded"

    # Now break it, the way a disk filling up mid-session does.
    import shutil
    shutil.rmtree(directory)
    directory.write_text("occupied")

    capsys.readouterr()                      # discard anything from install
    handler = server._mcp_server.request_handlers[types.CallToolRequest]
    assert await handler(_call_tool_request("console_send", {})) == "ok"

    captured = capsys.readouterr()
    assert captured.err == "", (
        "a per-request logging failure must not print; invariant 3 is that it "
        "costs one missing line and nothing else")


def test_write_log_line_reports_its_reason_and_still_never_raises(tmp_path):
    """The unit-level contract the two callers differ on."""
    from pare_worker_kit.serve import _write_log_line

    assert _write_log_line(str(tmp_path / "a" / "b.log"), "line\n") is None
    reason = _write_log_line(str(_unwritable_log_path(tmp_path)), "line\n")
    assert isinstance(reason, str) and reason, (
        "a failure must come back as a reason, not as None")
    assert "Error" in reason or "error" in reason or ":" in reason
