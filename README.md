# pare-worker-kit

The server half of a PARE worker: the wire constants a worker and the daemon
must agree on, contained artifact paths, and `run_worker`.

Depends on `mcp` alone, so a worker on a Raspberry Pi stays small. For the
current public surface, `python -c "import pare_worker_kit as k;
print(k.__all__)"` — deliberately not listed here, because an earlier
version of this line described two names when there were eight, and the
follow-up note that caught it said eight when there were twelve.

## Why this exists separately

A PARE worker runs on the machine that owns its hardware. That may be a
headless inference server, a laptop with an Android emulator attached, or a
Raspberry Pi wired to a Tigard on a bench.

The workers used to import `agent_core.workers.risk` to obtain one string.
Measured, that loads **21 `agent_core` modules** — including the client pool,
the worker manager, the risk-aware tool pool and the daemon's shell tool — and
declaring `agent_core` as a dependency would additionally install
`trafilatura`, `markitdown[pdf,docx,pptx,xlsx]`, `rich` and `prompt-toolkit`.
On a Pi, for a constant and a forty-line wrapper.

The direction was also backwards. `agent_core` is the **client** side:
transport, enforcement, lifecycle. `run_worker` is the **server** side.
Shipping it from `agent_core` would mean the machine being protected from the
worker also ships the code the worker runs.

So: one dependency, `mcp`. Adding a second re-creates the problem this package
was made to solve.

## Use

```python
from mcp.server.fastmcp import FastMCP
from pare_worker_kit import RISK_TIER_META_KEY, run_worker

def build_server() -> FastMCP:
    server = FastMCP("pare-example-mcp")
    server.add_tool(handler, name="example_read",
                    meta={RISK_TIER_META_KEY: "low"})
    return server

def main() -> None:
    run_worker(build_server())
```

`RISK_TIER_META_KEY` is how a tool advertises its risk tier over the wire. The
daemon treats that tier as **escalate-only**: it can raise a tool above the
floor declared in `workers.yaml`, never lower it. A worker that lies about it
can only make itself more restricted.

## Launching

| Variable | Values | Default |
|---|---|---|
| `AGENT_WORKER_TRANSPORT` | `stdio`, `http` | `stdio` |
| `AGENT_WORKER_HOST` | address, or an interface name like `tailscale0` | `127.0.0.1` |
| `AGENT_WORKER_PORT` | 1–65535 | none — required for `http` |

```ini
# /etc/systemd/system/pare-frida-mcp.service
[Unit]
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Environment=AGENT_WORKER_TRANSPORT=http
Environment=AGENT_WORKER_HOST=tailscale0
Environment=AGENT_WORKER_PORT=9101
ExecStart=/opt/pare/bin/pare-frida-mcp
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## What it refuses, and why

**A wildcard bind.** These workers have no application-level authentication.
The trust boundary is a Tailscale tailnet plus the operator's LAN, so
*anything that can route to the port can call any tool the worker exposes* —
and the bind address is the only thing enforcing that. A string comparison
against `"0.0.0.0"` is not enough: `0`, `0x0`, `00.0.0.0`, `::` and `::0` all
bind the wildcard too, and with `net.ipv6.bindv6only=0` (the Linux default)
`::` accepts IPv4 as well. The check is
`ipaddress.ip_address(host).is_unspecified`, against the address the name
actually resolves to — resolved here, so that what is validated is what is
bound.

The interface-name path exists so that refusal is defensible rather than
merely obstructive: "I can't know my IP ahead of time" is the one honest
reason to reach for `0.0.0.0`, and naming the interface answers it.

**An `http` launch with no port.** There is no default. Two workers on one
laptop would both take it, and the second would die inside uvicorn with a
socket error rather than here with a configuration one.

**`stateless_http`.** The MCP session id is currently the only thing that
surfaces a worker restart to the daemon. Without it, a `scope: session`
approval can survive onto a different process — approved for one worker,
spent on another.

DNS-rebinding protection is turned **on**; the SDK ships the middleware and
disables it whenever no settings are passed, which is what FastMCP does.
`run_worker` already knows the host and port, so declaring them costs a line.

## Related

- `agent_core` — the client side. It does **not** import this package; it
  states the shared wire constants as its own literals, because the daemon and
  a worker are installed separately and never share a Python environment. Each
  side carries a guard test asserting the other's values match when it is
  installed. Two definitions, deliberately, kept honest by tests — not one
  definition re-exported, which is what this section used to claim.
- `PARE/docs/superpowers/specs/2026-09-05-networked-workers-design.md` — the
  design this implements, including the trust-boundary decision and what
  would invalidate it.
