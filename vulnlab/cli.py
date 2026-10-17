"""vulnlab command-line front end.

    python -m vulnlab list
    python -m vulnlab start <machine> [machine...] [--all] [--host HOST]
    python -m vulnlab status
    python -m vulnlab stop   <machine> | --all
    python -m vulnlab ports  <machine>   # port list for pipelines
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import subprocess
import sys

from . import engine
from . import __version__
from .machines import MACHINES, get, machine_ports


def _slug_table() -> str:
    rows = [f"  {slug:<20} {m.name:<22} {len(m.services)} services  "
            f"ports {', '.join(str(p) for p in machine_ports(m))}"
            for slug, m in MACHINES.items()]
    return "\n".join(rows)


def cmd_list(_args) -> int:
    print("vulnlab machines:")
    print(_slug_table())
    print("\nstart one:   python -m vulnlab start <machine>")
    print("start every: python -m vulnlab start --all")
    return 0


def cmd_ports(args) -> int:
    m = get(args.machines[0])
    print(",".join(str(p) for p in machine_ports(m)))
    return 0


async def _run_machines(args, machines) -> int:
    tasks: dict[str, asyncio.Task] = {}
    bound: dict[str, dict[str, int]] = {}
    failures: dict[str, str] = {}
    for machine in machines:
        bound[machine.slug] = {}
        tasks[machine.slug] = asyncio.ensure_future(
            engine.serve(machine, args.host, bound_out=bound[machine.slug]))
    # wait until every machine has bound its ports (TLS cert minting may
    # spawn openssl), or a task dies trying
    deadline = asyncio.get_running_loop().time() + 15
    while asyncio.get_running_loop().time() < deadline:
        if all(bound[s] for s in tasks):
            break
        if any(t.done() for t in tasks.values()):
            break
        await asyncio.sleep(0.1)
    for slug, task in list(tasks.items()):
        if task.done():
            exc = task.exception()
            failures[slug] = str(exc) or repr(exc)
            del tasks[slug]
            bound.pop(slug, None)
    if not tasks:
        for slug, msg in failures.items():
            print(f"error starting {slug}: {msg}", file=sys.stderr)
        return 1
    print()
    print(f"vulnlab {__version__} — {len(tasks)} machine(s) listening on "
          f"{args.host}.  Ctrl+C to stop.", flush=True)
    for slug, task in tasks.items():
        m = MACHINES[slug]
        print(f"\n  [{slug}] {m.name}", flush=True)
        engine.register_instance(slug, args.host,
                                 {k: v for k, v in bound[slug].items()})
        for service in m.services:
            canon = service.port if service.port is not None \
                else service.fallback_port
            actual = bound[slug].get(service.name)
            tls_note = (f"  [{service.tls}]" if service.tls else "")
            shifted = f"  (port {canon} reserved, using {actual})" \
                if actual and canon and actual != canon else ""
            print(f"    :{canon:<7} {service.name:<15}{tls_note}{shifted}")
        actual_ports = sorted({v for v in bound[slug].values()
                               if isinstance(v, int)})
        scanned = ','.join(str(p) for p in actual_ports) if actual_ports \
            else ','.join(str(p) for p in machine_ports(m))
        if actual_ports and actual_ports != machine_ports(m):
            shown = ','.join(str(p) for p in actual_ports)
            print(f"    scan with: python -m vulnscan {args.host} -p {shown}")
        else:
            print(f"    scan with: python -m vulnscan {args.host} "
                  f"-p {scanned}", flush=True)
    if failures:
        print("\nfailed to start: " + ", ".join(sorted(failures)) +
              " (see messages above)", file=sys.stderr)
    try:
        await asyncio.gather(*tasks.values())
    except asyncio.CancelledError:
        pass
    finally:
        for task in tasks.values():
            task.cancel()
    return 0


def cmd_start(args) -> int:
    if args.all:
        machines = [MACHINES[s] for s in sorted(MACHINES)]
    else:
        if not args.machines:
            print("usage: python -m vulnlab start <machine> [--all]",
                  file=sys.stderr)
            print("run `python -m vulnlab list` for the catalog",
                  file=sys.stderr)
            return 2
        machines = [get(s) for s in args.machines]
    try:
        return asyncio.run(_run_machines(args, machines))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            engine.remove_instance()
        except Exception:
            pass
    return 0


def cmd_status(_args) -> int:
    state = engine._read_state()
    instances = state.get("instances", [])
    if not instances:
        print("no vulnlab instances are running "
              "(start one: python -m vulnlab start <machine>)")
        return 0
    for inst in instances:
        pid = inst.get("pid")
        per_machine = inst.get("ports", {})   # {machine: {service: port}}
        flat = sorted({v for contents in per_machine.values()
                       if isinstance(contents, dict)
                       for v in contents.values() if isinstance(v, int)}
                      | {v for v in per_machine.values()
                         if isinstance(v, int)})
        alive = bool(engine.pid_alive(pid)) if pid else False
        reachable = [ok for ok in engine.check_ports(
            inst.get("host", "127.0.0.1"), flat)] if flat else []
        label = ("RUNNING" if alive or all(reachable)
                 else "UNREACHABLE" if any(reachable) else "STOPPED")
        print(f"  pid {pid}: {', '.join(inst.get('slugs', [])):<44} "
              f"{inst.get('host')} ports {flat} [{label}]")
    return 0


def cmd_stop(args) -> int:
    state = engine._read_state()
    instances = state.get("instances", [])
    wanted = None if args.all else set(args.machines)
    killed = 0
    remaining = []
    for inst in instances:
        pid = inst.get("pid")
        if wanted is None or inst.get("slug") in wanted:
            if not pid or pid == os.getpid():
                continue
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   capture_output=True)
                else:
                    os.kill(pid, signal.SIGTERM)
                killed += 1
                print(f"stopped {', '.join(inst.get('slugs', []))} (pid {pid})")
            except OSError as exc:
                print(f"could not stop pid {pid}: {exc}", file=sys.stderr)
                remaining.append(inst)
        else:
            remaining.append(inst)
    try:
        engine._write_state({"instances": remaining})
    except Exception:
        pass
    if not killed:
        print("nothing to stop (no instances registered — start one first)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnlab",
        description="Deliberately vulnerable machines for security-tool testing.")
    p.add_argument("--version", action="version",
                   version=f"vulnlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="show the machine catalog").set_defaults(fn=cmd_list)

    sp = sub.add_parser("start", help="start machine(s) (Ctrl+C to stop)")
    sp.add_argument("machines", nargs="*", help="machine slugs")
    sp.add_argument("--all", action="store_true", help="start every machine")
    sp.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1 — keep it that way "
                         "for lab safety)")
    sp.set_defaults(fn=cmd_start)

    sub.add_parser("status", help="show running instances").set_defaults(fn=cmd_status)

    sp = sub.add_parser("stop", help="stop background instance(s)")
    sp.add_argument("machines", nargs="*", help="machine slugs")
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(fn=cmd_stop)

    sp = sub.add_parser("ports", help="print a machine's canonical ports")
    sp.add_argument("machines", nargs=1)
    sp.set_defaults(fn=cmd_ports)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
