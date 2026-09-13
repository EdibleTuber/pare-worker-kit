"""run_worker: serve a FastMCP worker over stdio or Streamable HTTP.

One binary, either transport, chosen at launch by environment variable. The
tool code does not change.

    AGENT_WORKER_TRANSPORT   stdio | http          (default: stdio)
    AGENT_WORKER_HOST        address or interface  (default: 127.0.0.1)
    AGENT_WORKER_PORT        port                  (required when http)
    AGENT_WORKER_REQUEST_LOG path to the request log (default: see below)

The bind address is the access control. This deployment has no
application-level authentication -- the trust boundary is a Tailscale
tailnet plus the operator's LAN -- so anything that can route to the port
can call any tool the worker exposes. That is a deliberate decision, and it
only holds while the port is not on a wildcard. Hence _resolve_host().

Over stdio, the daemon spawned the worker and holds its pipe, so the
daemon's own audit log is already a total record of what the worker did.
Over HTTP that stops being true -- anything that can route to the port can
call a tool directly, and the daemon never sees it. So the HTTP path alone
also keeps its OWN request log: peer address, tool name, a timestamp, and a
salted hash of the arguments (never the argument values -- a console `send`
may carry credentials typed at a target's prompt). The peer address is the
accepted connection's, not a header's: the HTTP path serves with uvicorn's
`proxy_headers` switched OFF, because uvicorn otherwise rewrites it from
`X-Forwarded-For` for any connection from 127.0.0.1 -- which is this
module's own DEFAULT_HOST. See `_uvicorn_ignoring_forwarded_headers`.

The log defaults to $XDG_STATE_HOME/pare-worker/requests.log, or
~/.local/state/pare-worker/requests.log if that is unset. A failure to write
it never fails the request that produced it -- but a failure to write it at
LAUNCH is announced on stderr, because an audit control that silently stops
auditing is the failure this whole feature exists to prevent.

The hash is for correlation, not confidentiality: its salt is written into
the same file, so a short argument value is recoverable by brute force by
anyone who can already read the log -- see `_record_request`.
"""
from __future__ import annotations

import contextlib
import hashlib
import inspect
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
from datetime import datetime, timezone
from typing import Any

__all__ = ["run_worker", "resolve_bind_address", "stamp_version",
           "WorkerServeError"]

DEFAULT_HOST = "127.0.0.1"
"""Loopback, so a worker launched with no configuration is not exposed."""

_SIOCGIFADDR = 0x8915
"""Linux ioctl for an interface's IPv4 address. The Pi and the laptop are
Linux; on anything else an interface name simply is not resolvable and the
operator gets told to write an address."""


class WorkerServeError(RuntimeError):
    """A launch that would have been wrong -- raised before any bind."""


def _interface_address(name: str) -> str | None:
    """The IPv4 address currently assigned to a named interface.

    This exists so the wildcard refusal is defensible rather than merely
    obstructive. A container, or a Pi that just booted onto a tailnet, often
    genuinely cannot name its address in a unit file -- and "I can't know my
    IP" is the one honest reason to reach for 0.0.0.0. Naming the interface
    answers it without opening the bind.
    """
    try:
        import fcntl
        import struct
    except ImportError:                      # not Linux
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR,
                             struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None                          # no such interface, or no IPv4 yet
    finally:
        sock.close()



def _interfaces_with_ipv4() -> list[tuple[str, str]]:
    """Every interface that currently has an IPv4 address, for error messages.

    Reads /proc/net/dev for names and asks the kernel for each address, rather
    than shelling out to `ip`: a worker may be on a minimal image with no
    iproute2, and an error path must not itself fail.
    """
    found: list[tuple[str, str]] = []
    try:
        with open("/proc/net/dev") as fh:
            names = [line.split(":")[0].strip()
                     for line in fh.read().splitlines()[2:] if ":" in line]
    except OSError:
        return found
    for name in names:
        addr = _interface_address(name)
        if addr:
            found.append((name, addr))
    return found


def _interface_hint() -> str:
    """What to try instead. A refusal that does not name the alternatives makes
    the operator go and find them by hand, which is the step this exists to
    save -- and on a headless Pi at a bench it is the slow step."""
    available = _interfaces_with_ipv4()
    if not available:
        return ("No interface on this machine currently has an IPv4 address. "
                "If you expected a tailnet interface, the daemon may not be up "
                "yet: check `tailscale status`.")
    listed = ", ".join(f"{n} ({a})" for n, a in available)
    return (f"Interfaces with an IPv4 address right now: {listed}. "
            f"Use one of those names, or the address itself.")


def resolve_bind_address(host: str) -> str:
    """Turn what the operator wrote into the literal address we will bind.

    Resolution happens HERE, not in uvicorn, so that the thing validated is
    the thing bound -- otherwise a name could pass the check and resolve to
    something else at bind time.

    Refuses every spelling of a wildcard. String comparison against "0.0.0.0"
    is not enough: on a stock Linux host '0', '0x0', '00.0.0.0', '::' and
    '::0' all bind the wildcard too, and with net.ipv6.bindv6only=0 (the
    default) '::' accepts IPv4 as well.
    """
    host = host.strip()
    if not host:
        raise WorkerServeError("host is empty; set a loopback or tailnet address")

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is None:
        iface = _interface_address(host)
        if iface is not None:
            addr = ipaddress.ip_address(iface)
        else:
            try:
                info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise WorkerServeError(
                    f"host {host!r} is neither an IP address, a network "
                    f"interface on this machine, nor a resolvable name: {exc}."
                    f"\n{_interface_hint()}"
                ) from exc
            addr = ipaddress.ip_address(info[0][4][0])

    if addr.is_unspecified:
        raise WorkerServeError(
            f"refusing to bind the wildcard address ({host!r} resolves to "
            f"{addr}). This worker has no authentication: the bind address "
            f"is the access control, and a wildcard exposes every tool to "
            f"every network this machine is on. Set AGENT_WORKER_HOST to the "
            f"tailnet address, or to an interface name such as 'tailscale0' "
            f"if the address is not known ahead of time."
        )
    return str(addr)


def _port_from_env(raw: str | None, var: str) -> int:
    """No default. A shared default is worse than a missing one: two workers
    on one laptop would both take it, and the second would die inside uvicorn
    rather than here, with a message about a socket rather than about
    configuration."""
    if raw is None or not raw.strip():
        raise WorkerServeError(
            f"{var} is required when serving over http; there is no default "
            f"port, because two workers sharing one would collide"
        )
    try:
        port = int(raw)
    except ValueError as exc:
        raise WorkerServeError(f"{var}={raw!r} is not a number") from exc
    if not 1 <= port <= 65535:
        raise WorkerServeError(f"{var}={port} is outside 1-65535")
    return port


def _apply_http_settings(server: Any, host: str, port: int) -> bool:
    """Configure host, port and transport security. Returns True if the
    server's own settings object took them.

    There are TWO different classes named FastMCP in this ecosystem:
    mcp.server.fastmcp.FastMCP (bundled in the SDK, what the workers use),
    whose run() reads host/port from self.settings and accepts neither as a
    kwarg; and the standalone fastmcp package's FastMCP (what agent_core's
    conformance fixture uses), whose run() takes them as kwargs. Branching on
    the object rather than assuming one keeps the fixture and production from
    drifting apart.
    """
    settings = getattr(server, "settings", None)
    if settings is None or not hasattr(settings, "host"):
        return False
    settings.host = host
    settings.port = port

    if hasattr(settings, "transport_security"):
        try:
            from mcp.server.transport_security import TransportSecuritySettings
        except ImportError:                                   # pragma: no cover
            return True
        # Off by default whenever no settings are passed, which is what
        # FastMCP does. Defence in depth: we already know the host and port,
        # so declaring them costs one line.
        settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"{host}:{port}", host],
            allowed_origins=[f"http://{host}:{port}"],
        )

    if getattr(settings, "stateless_http", False):
        # Session ids are the only thing that currently surfaces a worker
        # restart to the daemon. Without them a scope: session approval can
        # survive onto a different process, unnoticed.
        raise WorkerServeError(
            "stateless_http is set, which removes the MCP session id. The "
            "daemon uses that id to notice a worker restarting under a live "
            "approval; without it a session-scoped approval can outlive the "
            "process it was granted for."
        )
    return True



def _default_request_log_path() -> str:
    """Where the log goes when the operator has not said.

    Under the invoking user's own state directory, not a system path such as
    /var/log: a worker on a Pi at a bench is commonly started as an
    unprivileged user, and a default this function cannot write to would
    make the FIRST request the one that silently loses its record.
    XDG_STATE_HOME is respected for anyone who has set it.
    """
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "pare-worker", "requests.log")


_SAFE_TOOL_NAME_CHAR = re.compile(r"[A-Za-z0-9_.\-]")
"""The identifier set every real tool name in this system uses."""

_SAFE_PEER_CHAR = re.compile(r"[A-Za-z0-9_.\-:%]")
"""The tool-name set plus `:` and `%`, which a peer legitimately contains.

A peer is written `host:port`, and `host` may be an IPv6 literal
(`fe80::1`) with an optional zone id (`fe80::1%eth0`). The property the
record's grammar actually needs from a field value is narrower than "looks
like an identifier": fields are ` key=value` pairs on one line, so a value
must not contain a space, an `=`, or a newline. `:` and `%` violate none of
those, so admitting them keeps `peer=100.64.0.7:53214` and
`peer=fe80::1%eth0:53214` readable without weakening the record. The
escaping below stays a whitelist in both cases -- only the alphabet differs.
"""


def _escape_for_log(value: str, safe: re.Pattern[str]) -> str:
    """Make an untrusted string safe to interpolate into a single-line,
    space-delimited log record.

    Both values interpolated into a record -- the tool name and the peer --
    are attacker-influenced (see `_sanitize_tool_name` and `_peer_address`).
    Left unescaped, either could contain a newline and write extra fake
    lines into the file, or contain the literal text " peer=", " tool=" or
    " args_sha256=" and forge a field within a single line -- in both cases
    making the log an attack surface against the exact audit trail it
    exists to provide, before the tool call is even validated as real.

    Every character outside `safe` is replaced by its escaped hex form,
    which by construction cannot itself contain a space, `=`, or newline.
    The escaping is total, not a blocklist of the three known tokens above:
    a blocklist only ever covers the attacks someone thought of first.
    """
    if value and all(safe.fullmatch(c) for c in value):
        return value
    escaped = []
    for ch in value:
        if safe.fullmatch(ch):
            escaped.append(ch)
        else:
            escaped.extend(f"\\x{b:02x}" for b in ch.encode("utf-8", "replace"))
    return "".join(escaped)


def _sanitize_tool_name(name: str) -> str:
    """`CallToolRequestParams.name` is a bare `str` with no pattern
    constraint, and the module docstring's own threat model is "anything
    that can route to the port" -- so `name` is attacker-controlled."""
    return _escape_for_log(name, _SAFE_TOOL_NAME_CHAR)


def _sanitize_peer(peer: str) -> str:
    """Defence in depth behind `proxy_headers=False` -- see `_peer_address`
    for why a peer can be attacker-controlled at all, and
    `_uvicorn_ignoring_forwarded_headers` for the primary fix."""
    return _escape_for_log(peer, _SAFE_PEER_CHAR)


def _peer_address(mcp_server: Any) -> str:
    """The caller's address for the request currently being handled.

    mcp attaches the transport's Starlette Request to the low-level
    server's request-context ONLY for HTTP-shaped transports (streamable
    HTTP, SSE); a stdio session never constructs one, so this is also the
    mechanism that makes the hook a no-op if it were ever reached from
    stdio. Every step here is best-effort: this runs inside the logging
    path, and the logging path must never be why a request fails.

    WHERE THIS VALUE COMES FROM, stated accurately -- an earlier version of
    this docstring claimed it "comes from the OS's own idea of who
    connected the socket ... not from anything inside the JSON-RPC payload
    an attacker controls", and that was FALSE under this package's own
    default bind. `Request.client` is `scope["client"]`, and uvicorn
    defaults to `proxy_headers=True` with `forwarded_allow_ips="127.0.0.1"`
    -- so it wraps the app in `ProxyHeadersMiddleware`, which OVERWRITES
    `scope["client"]` from the `X-Forwarded-For` header whenever the
    connection arrives from a trusted host. `DEFAULT_HOST` here is
    `127.0.0.1`, which is exactly that trusted host, and
    `mcp.server.fastmcp.FastMCP` builds its `uvicorn.Config` with only
    app/host/port/log_level, so it never turns the behaviour off. On the
    kit's own default bind, one request header therefore chose what this
    function returned -- including the daemon's own address, which made the
    log answer "did PARE do it?" with a forged yes.

    `_uvicorn_ignoring_forwarded_headers` is the fix: `proxy_headers=False`
    at the uvicorn layer, so `scope["client"]` is once again only the
    accepted connection. `_sanitize_peer` below is defence in depth behind
    it, NOT the fix -- a same-host TLS terminator, nginx, or SSH tunnel that
    legitimately sets `X-Forwarded-For` reopens the question of whether the
    string is trustworthy regardless of bind, and the log's format must not
    additionally be forgeable by whatever ends up in it. Escaping makes a
    peer value unable to fabricate a FIELD; only `proxy_headers=False` makes
    it unable to fabricate an ADDRESS.
    """
    try:
        request = mcp_server.request_context.request
    except LookupError:
        return "unknown"
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    if not host:
        return "unknown"
    port = getattr(client, "port", None)
    peer = f"{host}:{port}" if port is not None else str(host)
    return _sanitize_peer(peer)


def _uvicorn_can_ignore_forwarded_headers() -> tuple[bool, str]:
    """Whether `_uvicorn_ignoring_forwarded_headers` can do its job here.

    Checked BEFORE serving so the answer can be said out loud and written
    into the log header, rather than discovered after a bricked target.
    `uvicorn` is not this package's dependency -- it arrives underneath
    `mcp`, which is unpinned as to uvicorn version -- so both the import and
    the parameter are things that can go away without this package changing.
    """
    try:
        import uvicorn
    except ImportError as exc:                                # pragma: no cover
        return False, f"uvicorn could not be imported ({exc})"
    try:
        params = inspect.signature(uvicorn.Config.__init__).parameters
    except (TypeError, ValueError) as exc:                    # pragma: no cover
        return False, f"uvicorn.Config's signature could not be read ({exc})"
    if "proxy_headers" not in params:                         # pragma: no cover
        return False, ("this uvicorn's Config takes no proxy_headers "
                       "argument, so its X-Forwarded-For handling cannot be "
                       "switched off from here")
    return True, ""


@contextlib.contextmanager
def _uvicorn_ignoring_forwarded_headers(enabled: bool = True):
    """Serve with uvicorn's X-Forwarded-For handling OFF.

    THE PROBLEM. uvicorn's `Config` defaults to `proxy_headers=True` and
    `forwarded_allow_ips="127.0.0.1"`, and `Config.load()` then wraps the
    app in `ProxyHeadersMiddleware`, which replaces `scope["client"]` with
    whatever the `X-Forwarded-For` header says when the connection came from
    a trusted host. This package's `DEFAULT_HOST` is `127.0.0.1`. So under
    the kit's own default, any client that can reach the port can dictate
    the `peer=` field of every record it produces -- including setting it to
    the daemon's address, which turns this log from evidence into a forgery
    tool aimed at the one question it exists to answer.

    WHY IT IS DONE THIS WAY. There is no supported route: `FastMCP.run()`
    takes only `transport` and `mount_path`, `FastMCP.run_streamable_http_
    async()` takes no arguments at all, and it constructs
    `uvicorn.Config(app, host=..., port=..., log_level=...)` internally with
    no hook of any kind. Reconstructing the app ourselves
    (`server.streamable_http_app()` + our own `uvicorn.Server`) was the
    alternative and is worse: it hard-codes SDK internals that the pin
    (`mcp>=1.27.0,<2`) explicitly allows to move, and it would not cover the
    standalone `fastmcp` package that `_apply_http_settings` also supports.
    Overriding the two attributes on every `Config` built while we are
    serving covers both, and touches nothing else.

    `Config.__init__` does not call `Config.load()`; `Server.serve()` does,
    and `load()` reads `self.proxy_headers` at that point -- which is why
    setting the attribute after construction is sufficient, and why it is
    done that way rather than by injecting a keyword argument into a
    signature whose parameters are all positional-or-keyword (a caller that
    passed `proxy_headers` positionally would then get "multiple values for
    argument", turning a hardening measure into a crash on serve).

    Scoped to the call and restored in `finally`: a process-global patch
    installed at import would change uvicorn for anything else sharing the
    interpreter, which for a library is not ours to do.
    """
    if not enabled:                                           # pragma: no cover
        yield
        return
    import uvicorn
    original = uvicorn.Config.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.proxy_headers = False
        # Unused once proxy_headers is False, but set anyway so that a
        # future uvicorn which re-derives the middleware from this field
        # alone still trusts nothing.
        self.forwarded_allow_ips = []

    uvicorn.Config.__init__ = patched
    try:
        yield
    finally:
        uvicorn.Config.__init__ = original


def _warn_peer_addresses_unverified(reason: str) -> None:
    """Loud, for the same reason `_warn_request_log_disabled` is: a log that
    records a peer it cannot vouch for is worse than one that says so."""
    print(
        f"{_program_name()}: request-log peer addresses are NOT VERIFIED for "
        f"this process -- {reason}. If anything can set X-Forwarded-For on a "
        f"connection this worker trusts, the peer= field in the request log "
        f"is attacker-controlled and must not be treated as evidence.",
        file=sys.stderr, flush=True,
    )


_PROCESS_SALT: str | None = None


def _request_log_salt() -> str:
    """One random salt per process, used to hash every request this process
    logs.

    This is NOT key management and does not make the hash a place secrets
    can safely live -- the salt is written into the log itself (see
    `_install_request_log`), so anyone who can read the log can read the
    salt next to it. What it buys: a table of sha256(short-guess) values
    precomputed ONCE, offline, before ever seeing this file cannot be
    reused against it, and the same table cannot be reused across a
    restart or across another worker either, because each process rolls
    its own salt. An attacker who already has the log and is willing to
    compute after reading it is unaffected -- see the residual-limit note
    on `_record_request`.
    """
    global _PROCESS_SALT
    if _PROCESS_SALT is None:
        _PROCESS_SALT = secrets.token_hex(16)
    return _PROCESS_SALT


def _write_log_line(log_path: str, line: str) -> str | None:
    """The one place that touches the filesystem for this feature, so the
    swallow-everything behaviour (invariant 3) lives in exactly one spot.

    Returns None on success, or a short description of the failure. It
    still raises nothing, ever -- but the RESULT is now how the two callers
    differ, and the asymmetry between them is the point:

    * `_install_request_log` calls this ONCE, at launch, and checks the
      result. A path that cannot be written is a control that will never
      audit anything, and it must say so before the worker starts taking
      requests -- an unwritable `AGENT_WORKER_REQUEST_LOG`, a read-only
      mount or a full SD card used to produce a successful-looking install
      with a silently dead audit trail, which is precisely the "PARE cannot
      establish whether it did it" failure this feature exists to close.
    * `_record_request` calls it per request and IGNORES the result
      (invariant 3). A full disk must cost one missing line, never a live
      hardware call -- taking a bench offline because a log line did not
      fit is a worse outcome than the gap in the log.

    Refusing to start loudly and never breaking a live request are not in
    tension; they are the two halves of the same rule, applied at the two
    moments where the right answer differs.
    """
    try:
        directory = os.path.dirname(log_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def _record_request(mcp_server: Any, log_path: str, req: Any) -> None:
    """Append one line: timestamp, peer, tool, and a hash of the arguments.

    Never the arguments themselves (invariant 1) -- a console `send` payload
    can carry credentials typed at a target's login prompt, and the hash
    answers "was this the same call" without giving those credentials a new
    place to live. Arguments are canonicalised (sorted keys) before hashing
    so the same call hashes the same way regardless of the key order a
    particular client happened to send, and salted per-process (see
    `_request_log_salt`) so a table precomputed before this file existed is
    not reusable against it.

    RESIDUAL LIMIT, stated plainly rather than implied: this hash is for
    correlation ("was this the same call as that other line"), not
    confidentiality. A short argument value -- a short password, a short
    data_b64 payload -- is recoverable by brute force by anyone who can
    already read this file, salt included, because the salt is stored right
    next to the hash it salts. Do not treat this file as a place a secret is
    safe merely because it is hashed.

    Every exception is swallowed (invariant 3): a full disk, a missing
    directory, a permissions error, or an unhashable argument must cost the
    operator one missing log line, never the request that produced it.
    """
    try:
        tool = _sanitize_tool_name(getattr(req.params, "name", None) or "?")
        arguments = getattr(req.params, "arguments", None) or {}
        salt = _request_log_salt()
        canonical = json.dumps(arguments, sort_keys=True, default=str)
        digest = hashlib.sha256(
            (salt + canonical).encode("utf-8", "replace")
        ).hexdigest()
        peer = _peer_address(mcp_server)
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        line = f"{ts} peer={peer} tool={tool} args_sha256={digest}\n"
        _write_log_line(log_path, line)
    except Exception:
        pass


def _warn_request_log_disabled(reason: str) -> None:
    """Loud, not silent: an audit control that quietly stops auditing is
    worse than one that visibly refuses to start. `_install_request_log`
    only runs once, at launch, so this is not a per-request spam risk in
    production -- it fires at most once per worker process."""
    print(
        f"{_program_name()}: request logging is DISABLED for this process "
        f"-- {reason}. Networked-transport tool calls will NOT be audited "
        f"until this is fixed.",
        file=sys.stderr, flush=True,
    )


def _install_request_log(server: Any, *, env: dict[str, str], env_prefix: str,
                         forwarded_for: str = "unknown") -> None:
    """Make every tool call over THIS transport record itself, independent
    of the daemon (invariant 2: the log must survive the daemon, so it is a
    file on the worker's own disk, not something held only in the daemon's
    memory).

    Only called from the HTTP branch of `_run_worker` -- stdio workers are
    unaffected (invariant 4), because over stdio the daemon spawned the
    child and holds its pipe, so the daemon's own audit log already is a
    total record; over HTTP anything that can route to the port can call a
    tool directly and the daemon never sees it.

    Why this patches `request_handlers[CallToolRequest]` rather than
    wrapping `server.call_tool`: `FastMCP.__init__` calls
    `self._mcp_server.call_tool(validate_input=False)(self.call_tool)`
    during construction, which closes the low-level dispatcher over the
    bound method it was handed AT THAT TIME. `server` reaches `run_worker`
    already constructed, so reassigning the `call_tool` attribute on the
    instance would rebind a name that closure no longer looks up.
    `request_handlers` is a plain dict read at dispatch time, so replacing
    its entry is seen by every subsequent call.

    Every no-op path below is loud (`_warn_request_log_disabled`), not a
    silent `return`. `mcp` is pinned to a range (`>=1.27.0,<2`), not a
    single version; a routine upgrade inside that range could rename or
    restructure any of `_mcp_server`, `request_handlers`, or
    `CallToolRequest` without this package changing at all, and a worker
    that stopped auditing itself without saying so would be exactly the
    "PARE cannot establish whether it did it" failure this feature exists
    to close.
    """
    try:
        from mcp import types
    except ImportError:                                   # pragma: no cover
        _warn_request_log_disabled("could not import mcp.types")
        return
    mcp_server = getattr(server, "_mcp_server", None)
    if mcp_server is None:
        _warn_request_log_disabled(
            "the server object has no _mcp_server attribute; the mcp SDK's "
            "internal shape may have changed")
        return
    handlers = getattr(mcp_server, "request_handlers", None)
    if handlers is None:
        _warn_request_log_disabled(
            "server._mcp_server has no request_handlers dict; the mcp "
            "SDK's internal shape may have changed")
        return
    original = handlers.get(types.CallToolRequest)
    if original is None:
        _warn_request_log_disabled(
            "no CallToolRequest handler is registered yet; the mcp SDK's "
            "handler-registration order may have changed")
        return

    log_path = (env.get(f"{env_prefix}REQUEST_LOG")
                or _default_request_log_path())
    ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    # `forwarded_for` goes in the header because a reader months later has
    # to know whether the peer= fields below it are evidence or hearsay,
    # and the process that knew is long gone. See `_peer_address`.
    failure = _write_log_line(
        log_path,
        f"{ts} event=log_started salt={_request_log_salt()} "
        f"pid={os.getpid()} forwarded_for={_sanitize_peer(forwarded_for)}\n")
    if failure is not None:
        # The ONE write this feature does at launch, and the only one whose
        # failure can be reported before requests start arriving. Without
        # this check the install succeeded silently and every subsequent
        # record was dropped just as silently -- the exact failure
        # `_default_request_log_path` warns about, reached by a different
        # route (an explicit REQUEST_LOG the operator cannot write, a
        # read-only mount, a full disk).
        _warn_request_log_disabled(
            f"the log file {log_path!r} could not be written -- {failure}. "
            f"Check {env_prefix}REQUEST_LOG, the directory's permissions, "
            f"and free space")
        # The hook is still installed, deliberately. The condition may be
        # transient (a disk that frees up), and a hook costs nothing while
        # it fails; refusing to install would guarantee no records even
        # after the fault cleared. Nothing is raised either: a full disk
        # must not be why a hardware bench will not start. Note the
        # residual gap this leaves -- the salt line is what makes the
        # digests below it correlatable, so records written after a failed
        # header are hashes whose salt was never recorded.

    async def logged(req: Any) -> Any:
        # Recorded before the tool runs, not after: a hardware call that
        # hangs or crashes the process (the exact case this log exists for)
        # must still leave a record that it was attempted.
        _record_request(mcp_server, log_path, req)
        return await original(req)

    handlers[types.CallToolRequest] = logged


def stamp_version(server: Any, version: str | None = None) -> str | None:
    """Make the worker advertise its OWN version at initialize.

    Worth stating plainly, because the default is actively misleading:
    mcp.server.fastmcp.FastMCP takes no `version` argument, so the low-level
    Server it builds gets None, and the SDK then reports **its own version**
    as serverInfo.version. Measured against a real worker, a freshly built
    pare-static-mcp announced "1.29.1" -- the mcp library's version.

    That matters because the daemon records serverInfo as the provenance for
    a NETWORKED worker: it cannot spawn the process or stat a binary, so this
    is the only thing that can change when the remote build changes. A field
    that reports the SDK version instead is worse than absent, because it
    looks like provenance and stays constant across every redeploy.

    The version is looked up from installed package metadata using the
    server's own name (the workers name their FastMCP instance after their
    distribution). Best-effort: a worker running from a source tree with no
    metadata simply keeps whatever it had.
    """
    low = getattr(server, "_mcp_server", None)
    if low is None:
        return None
    if version is None:
        name = getattr(server, "name", None) or getattr(low, "name", None)
        if not name:
            return None
        try:
            from importlib.metadata import PackageNotFoundError, version as _v
        except ImportError:                                   # pragma: no cover
            return None
        try:
            version = _v(name)
        except PackageNotFoundError:
            return None
    low.version = version
    return version


def run_worker(server: Any, *, default_transport: str = "stdio",
               env_prefix: str = "AGENT_WORKER_",
               env: dict[str, str] | None = None) -> None:
    """Serve `server` over the transport the environment selects.

    Raises WorkerServeError, before binding anything, for every launch that
    would have been wrong.
    """
    try:
        _run_worker(server, default_transport=default_transport,
                    env_prefix=env_prefix, env=env)
    except WorkerServeError as exc:
        # A CONFIGURATION mistake is not a crash, and printing eight frames of
        # traceback for one buries the one line that says what to change.
        # Observed twice while bringing the first remote worker up: a missing
        # AGENT_WORKER_PORT and an unresolvable AGENT_WORKER_HOST each arrived
        # in the journal as a full Python stack, with the actionable sentence
        # last and truncated by journalctl's line wrapping.
        #
        # Exit 2 rather than 1, so a config refusal is distinguishable in
        # `systemctl status` from the worker failing at runtime.
        print(f"{_program_name()}: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2) from None


def _program_name() -> str:
    return os.path.basename(sys.argv[0]) or "pare-worker-kit"


def _run_worker(server: Any, *, default_transport: str, env_prefix: str,
                env: dict[str, str] | None) -> None:
    """The actual logic. Separate so tests can assert on WorkerServeError
    rather than on a SystemExit, and so the message-and-exit behaviour above
    stays a thin, obviously-correct wrapper."""
    env = os.environ if env is None else env
    # Before serving either way: the daemon reads serverInfo as a networked
    # worker's only provenance, and the SDK's default value is its own
    # version rather than ours.
    stamp_version(server)
    transport = (env.get(f"{env_prefix}TRANSPORT") or default_transport).strip().lower()

    if transport in ("stdio",):
        server.run(transport="stdio")
        return

    # WorkerSpec.transport is 'streamable_http' (underscore) and FastMCP.run
    # wants 'streamable-http' (hyphen). Accept both spellings from the
    # environment rather than making an operator remember which side they are
    # writing for.
    if transport not in ("http", "streamable_http", "streamable-http"):
        raise WorkerServeError(
            f"unknown transport {transport!r}; use 'stdio' or 'http'")

    host = resolve_bind_address(env.get(f"{env_prefix}HOST") or DEFAULT_HOST)
    port = _port_from_env(env.get(f"{env_prefix}PORT"), f"{env_prefix}PORT")

    took_settings = _apply_http_settings(server, host, port)

    # Before the log is installed, so its header can say which of the two
    # it is: uvicorn trusts X-Forwarded-For from 127.0.0.1 by default and
    # DEFAULT_HOST is 127.0.0.1, so without this the peer= field is a
    # request header rather than a socket. See
    # `_uvicorn_ignoring_forwarded_headers`.
    can_harden, why_not = _uvicorn_can_ignore_forwarded_headers()
    if not can_harden:                                        # pragma: no cover
        _warn_peer_addresses_unverified(why_not)

    # Only the HTTP branch reaches this: stdio returned above, so this is
    # exactly the boundary invariant 4 depends on.
    _install_request_log(server, env=env, env_prefix=env_prefix,
                         forwarded_for="ignored" if can_harden else "UNVERIFIED")
    with _uvicorn_ignoring_forwarded_headers(can_harden):
        if took_settings:
            server.run(transport="streamable-http")
        else:
            server.run(transport="streamable-http", host=host, port=port)
