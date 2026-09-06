"""run_worker: serve a FastMCP worker over stdio or Streamable HTTP.

One binary, either transport, chosen at launch by environment variable. The
tool code does not change.

    AGENT_WORKER_TRANSPORT   stdio | http          (default: stdio)
    AGENT_WORKER_HOST        address or interface  (default: 127.0.0.1)
    AGENT_WORKER_PORT        port                  (required when http)

The bind address is the access control. This deployment has no
application-level authentication -- the trust boundary is a Tailscale
tailnet plus the operator's LAN -- so anything that can route to the port
can call any tool the worker exposes. That is a deliberate decision, and it
only holds while the port is not on a wildcard. Hence _resolve_host().
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
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

    if _apply_http_settings(server, host, port):
        server.run(transport="streamable-http")
    else:
        server.run(transport="streamable-http", host=host, port=port)
