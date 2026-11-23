"""Command line for the human steps around the policy: keys, signing, learning, approval.

    refmon keygen KEYFILE                      write a new signing key; print the public key
    refmon init-policy OUT                     write the reference policy (unsigned)
    refmon sign POLICY KEYFILE                 sign a policy or rule pack in place
    refmon verify POLICY PUBLIC_KEY            check a signature and the policy
    refmon learn POLICY PUBLIC_KEY OUT EVENTS  count what roles do in replay files, write a proposal
    refmon approve PROPOSAL --by NAME          approve a proposal (--relax: relaxing changes too)
    refmon apply POLICY PROPOSAL OUT KEYFILE   apply an approved proposal and sign the result
    refmon audit [GOLDEN_DIR]                  run the privacy audit
    refmon scan-rootkit [--json]               run read-only multi-engine rootkit scanners
    refmon serve [--port PORT] [--workdir DIR] start live background barrier & web dashboard
          [--notify-webhook URL] [--notify-command CMD] [--notify-on block,hold,alert,...]
    refmon health [--workdir DIR] [--json]     is the daemon alive and healthy? (for cron)
    refmon guard [OPTS] -- COMMAND...          intercept and enforce policy on a command
    refmon lab [--list] [--run N ...]          interactive attack lab: templates judged, then run
    refmon browser-host [--workdir DIR]        native-messaging host for the browser extension
    refmon browser-install [--system]          install the host manifests for Firefox/Chromium
    refmon decoy plant|approve-canaries|refresh|sources|approve-source   deception (decoys.yaml)
    refmon ingest list|check                   connect external sensors (mapping files)

Nothing here runs unattended: a person holds the key and names themselves as approver.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import signing
from .admin import read_private_key
from .learning import (
    ContractLearner,
    apply_proposal,
    approve,
    read_proposal,
    write_proposal,
)
from .policy import default_policy_dict
from .policy_io import PolicyRejected, load_policy_data, read_document, write_document, write_signed
from .replay import ReplaySource


def _notify_args(parser: argparse.ArgumentParser) -> None:
    from .notify import CATEGORIES

    parser.add_argument(
        "--notify-webhook",
        action="append",
        default=[],
        metavar="URL",
        help="POST notifications as JSON to this URL (Slack/Mattermost incoming webhooks work); "
        "repeatable",
    )
    parser.add_argument(
        "--notify-command",
        action="append",
        default=[],
        metavar="CMD",
        help="run CMD (no shell) per notification, JSON on stdin, e.g. "
        "'mail -s Refmon you@example.org'; repeatable",
    )
    parser.add_argument(
        "--notify-on",
        default=None,
        metavar="LIST",
        help=f"categories for the webhook/command: comma list of {', '.join(CATEGORIES)} or all "
        "(default: block,hold,alert,rootkit,lifecycle; the log file and terminal get everything)",
    )


def _policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy",
        default=None,
        help="the signed policy (default: /etc/separ/policy.yaml as root, else "
        "$XDG_CONFIG_HOME/separ/policy.yaml); the daemon refuses to start without one",
    )
    parser.add_argument(
        "--public-key", default=None, help="the admin's public key (default: next to the policy)"
    )


def _build_hub(args: argparse.Namespace):
    import shlex

    from .notify import CommandChannel, NotificationHub, WebhookChannel, parse_categories

    external = [WebhookChannel(url) for url in args.notify_webhook]
    external += [CommandChannel(shlex.split(cmd)) for cmd in args.notify_command]
    return NotificationHub(external=external, external_categories=parse_categories(args.notify_on))


def main(argv: list[str] | None = None) -> int:
    prog_name = Path(sys.argv[0]).name if (sys.argv and sys.argv[0]) else "separ"
    if prog_name not in ("separ", "refmon"):
        prog_name = "separ"
    parser = argparse.ArgumentParser(prog=prog_name, description=__doc__.split("\n\n")[0])
    from . import __version__

    parser.add_argument("--version", action="version", version=f"separ {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser(
        "setup",
        help="guided policy and environment setup for servers or laptops",
        description=(
            "Initialize keys, sign policy (TUBAF campus subnets, domains, apps), "
            "and configure environment."
        ),
    )
    setup.add_argument(
        "--server", action="store_true", help="configure for campus server infrastructure"
    )
    setup.add_argument(
        "--laptop",
        action="store_true",
        help="configure for workstation / personal laptop endpoint",
    )
    setup.add_argument(
        "--mode",
        choices=("observe", "block", "warn"),
        default="observe",
        help="initial policy enforcement mode (default: observe)",
    )
    setup.add_argument(
        "--config-dir",
        "--workdir",
        dest="config_dir",
        default=None,
        help="where the daemon reads policy.yaml and admin.pub (default: /etc/separ as root, "
        "else $XDG_CONFIG_HOME/separ)",
    )
    setup.add_argument(
        "--key",
        default=None,
        help="the admin's private signing key (default ~/.separ-admin/admin.key; created if "
        "missing). Keep it on the admin's machine, never on the endpoints",
    )

    pol = sub.add_parser(
        "policy",
        help="show, sign or change the signed policy (admin side: needs the private key)",
        description="The daemon only verifies; every signature is made here with --key. After a "
        "change run `separ reload` (or systemctl reload separ).",
    )
    psub = pol.add_subparsers(dest="policy_command", required=True)
    for name in ("show", "sign", "set-mode"):
        pp = psub.add_parser(name)
        if name == "set-mode":
            pp.add_argument("mode", choices=("observe", "warn", "block"))
        pp.add_argument("--policy", default=None, help="default: <config dir>/policy.yaml")
        pp.add_argument("--public-key", default=None, help="default: next to the policy")
        if name != "show":
            pp.add_argument("--key", default=None, help="default ~/.separ-admin/admin.key")
        if name == "show":
            pp.add_argument("--json", action="store_true", dest="as_json")
    rl = sub.add_parser(
        "reload",
        help="tell the running daemon to re-read and verify its signed policy",
        description="Sends an authenticated /api/reload to the daemon of --workdir (SIGHUP to "
        "its pid when the API cannot be reached). The daemon never writes or signs a policy.",
    )
    rl.add_argument("--workdir", default=None, help="the daemon's work directory")
    rl.add_argument("--host", default="localhost")

    keygen = sub.add_parser("keygen")
    keygen.add_argument("keyfile")
    init = sub.add_parser("init-policy")
    init.add_argument("out")
    sign = sub.add_parser("sign")
    sign.add_argument("document")
    sign.add_argument("keyfile")
    verify = sub.add_parser("verify")
    verify.add_argument("policy")
    verify.add_argument("public_key")
    learn = sub.add_parser("learn")
    learn.add_argument("policy")
    learn.add_argument("public_key")
    learn.add_argument("out")
    learn.add_argument("events", nargs="+")
    appr = sub.add_parser("approve")
    appr.add_argument("proposal")
    appr.add_argument("--by", required=True)
    appr.add_argument("--relax", action="store_true")
    appr.add_argument("--only", nargs="*", default=None)
    audit = sub.add_parser("audit")
    audit.add_argument("golden", nargs="?")
    apply_ = sub.add_parser("apply")
    apply_.add_argument("policy")
    apply_.add_argument("proposal")
    apply_.add_argument("out")
    apply_.add_argument("keyfile")
    rk = sub.add_parser(
        "scan-rootkit",
        description="Read-only rootkit and stealth scan of this host.",
        epilog="exit codes: 0 allow (nothing to review), 1 hold (findings to review), 2 block",
    )
    rk.add_argument("--json", action="store_true", dest="as_json")
    rk.add_argument("--passes", type=int, default=2)
    rk.add_argument("--interval-ms", type=float, default=50.0)
    rk.add_argument("--with-external", action="store_true")
    rk.add_argument(
        "--strict-jit",
        action="store_true",
        help="also score anonymous rwx memory of JIT runtimes (node, java, Claude Code, ...)",
    )
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8765)
    srv.add_argument("--workdir", default=None)
    srv.add_argument("--decoys", default=None, help="decoys.yaml: run decoy services and watcher")
    srv.add_argument("--ingest", default=None, help="ingest.yaml: external sensors (mapping files)")
    _policy_args(srv)
    srv.add_argument(
        "--enforce",
        action="store_true",
        help="contain for real (SIGSTOP/SIGKILL, nftables, root quarantine); needs root. "
        "Default off: decisions are logged, containment is simulated",
    )
    _notify_args(srv)
    srv.add_argument(
        "--rootkit-interval",
        type=float,
        default=3600.0,
        help="seconds between rootkit scans while serving (0: only at start; default 3600)",
    )
    gui = sub.add_parser(
        "gui",
        help="launch interactive Reference Monitor GUI in desktop browser",
        description=(
            "Launch Separ's reference monitor interface. Similar to Wireshark for "
            "network packets, Separ GUI traces behavior, role contracts and security "
            "verdicts in real time, with visual and audio alerts for blocked attack attempts."
        ),
    )
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8765)
    gui.add_argument("--workdir", default=None)
    _policy_args(gui)
    gui.add_argument(
        "--no-browser",
        action="store_true",
        help="start daemon without auto-opening desktop browser",
    )
    _notify_args(gui)
    gui.add_argument(
        "--rootkit-interval",
        type=float,
        default=3600.0,
        help="seconds between rootkit scans while serving (0: only at start; default 3600)",
    )
    gui.add_argument(
        "--decoys",
        default=None,
        help="path to decoys.yaml or 'default' to install standard bait (design decision A75)",
    )
    gui.add_argument(
        "--ingest",
        default=None,
        help="path to ingest.yaml (or directory of .yaml configs) for external sensors (A76)",
    )
    hl = sub.add_parser(
        "health",
        description="Check a running `refmon serve` from outside, through its heartbeat file. "
        "Meant for cron or a systemd timer: it notifies once when the daemon dies or gets a "
        "problem, and once when it recovers.",
        epilog="exit codes: 0 healthy, 1 not running or heartbeat stale, 2 running with a problem",
    )
    hl.add_argument("--workdir", default=None, help="the daemon's work directory")
    hl.add_argument("--json", action="store_true", dest="as_json")
    _notify_args(hl)
    from .deception.cli import add_parser as add_decoy_parser
    from .ingest.cli import add_parser as add_ingest_parser

    add_decoy_parser(sub)
    add_ingest_parser(sub)
    bh = sub.add_parser(
        "browser-host",
        description="Native-messaging host started by the browser itself (not by hand): relays "
        "the extension's observations to the running daemon.",
    )
    bh.add_argument("--host", default="localhost")
    bh.add_argument("--port", type=int, default=None, help="default: the daemon's port file")
    bh.add_argument("--workdir", default=None)
    bh.add_argument("browser_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    bi = sub.add_parser(
        "browser-install",
        description="Write the launcher and the native-messaging manifests so the Refmon "
        "extension can reach this user's daemon (--system: for every user, as root).",
    )
    bi.add_argument("--system", action="store_true")
    bi.add_argument("--port", type=int, default=None, help="default: the daemon's port file")
    bi.add_argument("--workdir", default=None, help="daemon work directory (default: per user)")
    bi.add_argument("--launcher-dir", default=None)
    bi.add_argument("--chromium-extension-id", action="append", default=[], dest="chromium_ids")
    grd = sub.add_parser("guard")
    grd.add_argument("--host", default="localhost")
    grd.add_argument("--port", type=int, default=8765)
    grd.add_argument("--workdir", default=None)
    grd.add_argument(
        "--origin",
        default="web",
        choices=("web", "mail", "agent_input", "inbound_request", "download", "none"),
    )
    grd.add_argument("--role", default="interactive_shell")
    grd.add_argument("--no-exec", action="store_true")
    grd.add_argument("--json", action="store_true", dest="as_json")
    grd.add_argument("cmd_parts", nargs=argparse.REMAINDER)
    from .attacklab import GUIDE

    lab = sub.add_parser(
        "lab",
        help="interactive attack lab: pick an attack, Separ judges it before it runs",
        description="Interactive attack lab: attack templates go through the Separ pipeline "
        "before they may run. Without options it opens the menu.",
        epilog=GUIDE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lab.add_argument(
        "--workdir",
        default=None,
        help="lab folder: policy, keys, sandbox, logs/, runs/ (default <Separ>/attack-lab)",
    )
    lab.add_argument("--list", action="store_true", help="print all templates and exit")
    lab.add_argument(
        "--run",
        nargs="+",
        default=None,
        metavar="TEMPLATE",
        help="run templates without the menu: numbers, ids, ranges, all/attacks/benign/limits",
    )
    lab.add_argument(
        "--mode",
        choices=("block", "warn", "observe"),
        default=None,
        help="set the signed policy mode first (block enforces; warn/observe only log)",
    )
    lab.add_argument("--no-color", action="store_true", help="plain output")
    lab.add_argument("--table", action="store_true", help="print the table of all attacks and exit")
    lab.add_argument(
        "--test-all",
        action="store_true",
        help="run ALL templates and save every result (jsonl, csv, md, console.log)",
    )
    lab.add_argument("--save", action="store_true", help="with --run: also save the results")
    lab.add_argument(
        "--report-dir",
        default=None,
        help="where saved runs go (default <Separ>/attack-lab/runs; each run gets run-<time>/)",
    )
    lab.add_argument(
        "--analyze",
        nargs="?",
        const="",
        default=None,
        metavar="RUN_DIR",
        help="print the analysis of a saved run (default: the newest) and exit",
    )
    lab.add_argument(
        "--compare",
        nargs="+",
        default=None,
        metavar="RUN_DIR",
        help="compare saved runs side by side (decision per attack per run) and exit",
    )
    lab.add_argument(
        "--record-own-commands",
        action="store_true",
        help="store the text and output of your own $ commands in saved reports "
        "(default: an hmac fingerprint only)",
    )

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (PolicyRejected, PermissionError, ValueError, OSError) as error:
        print(f"separ: {error}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    if args.command == "setup":
        from .setup import run_setup

        return run_setup(args)
    elif args.command == "keygen":
        from .config import write_secret

        private, public = signing.generate_keypair()
        write_secret(Path(args.keyfile), private)  # 0600 from the start, never overwritten
        print(public)
    elif args.command == "policy":
        return _policy_command(args)
    elif args.command == "reload":
        return _reload_command(args)
    elif args.command == "init-policy":
        write_document(default_policy_dict(), args.out)
    elif args.command == "sign":
        document = read_document(args.document)
        write_signed(document, read_private_key(args.keyfile), args.document)
    elif args.command == "verify":
        loaded = load_policy_data(args.policy, [args.public_key.strip()])
        print(f"ok {loaded.digest} packs={len(loaded.packs)}")
    elif args.command == "learn":
        loaded = load_policy_data(args.policy, [args.public_key.strip()])
        learner = ContractLearner(loaded.policy)
        for events in args.events:
            learner.new_stream()
            for event in ReplaySource(events, extra_roles=loaded.policy.extra_roles):
                learner.learn(event)
        write_proposal(learner.proposal(), args.out)
        print(f"proposal written: {args.out}")
    elif args.command == "approve":
        proposal = read_proposal(args.proposal)
        only = set(args.only) if args.only is not None else None
        approved = approve(
            proposal,
            args.by,
            change_ids=only,
            include_relax=args.relax,
            at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        write_proposal(approved, args.proposal)
        print(f"approved {sum(c.approved for c in approved.changes())} changes")
    elif args.command == "audit":
        from .audit import main as audit_main

        return audit_main([args.golden] if args.golden else [])
    elif args.command == "apply":
        document = read_document(args.policy)
        data = apply_proposal(
            {k: v for k, v in document.items() if k != signing.SIGNATURE_FIELD},
            read_proposal(args.proposal),
        )
        write_signed(data, read_private_key(args.keyfile), args.out)
        print(f"signed policy written: {args.out}")
    elif args.command == "scan-rootkit":
        import json

        from .rootkit import ScanConfig, evaluate_rootkit_scan, format_scan_report
        from .schemas import Decision

        cfg = ScanConfig(
            passes=max(1, args.passes),
            pass_interval_s=max(0.0, args.interval_ms / 1000.0),
            run_external=args.with_external,
            strict_jit=args.strict_jit,
        )
        from .keys import new_device_key

        # fresh random key per run: fingerprints correlate within this report and reverse nowhere
        report, _ = evaluate_rootkit_scan(cfg, key=new_device_key())
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_scan_report(report))
        return {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.BLOCK: 2}[report.calculus_decision]
    elif args.command == "serve":
        from .live import serve_forever

        prog = Path(sys.argv[0]).name if (sys.argv and sys.argv[0]) else "separ"
        if prog not in ("separ", "refmon"):
            prog = "separ"

        try:
            hub = _build_hub(args)
        except ValueError as exc:
            print(f"{prog} serve: {exc}", file=sys.stderr)
            return 2
        ingest_cfg = args.ingest
        if not ingest_cfg and Path("/etc/separ/ingest.yaml").is_file():
            ingest_cfg = "/etc/separ/ingest.yaml"
        if not ingest_cfg:
            border = "=" * 74
            print(
                f"\n{border}\n"
                f"⚠️  {prog.upper()} NOTICE: External Server Sensors Not Configured!\n"
                f"{border}\n"
                "Running in local demonstration mode without external server sensors.\n"
                "To monitor and protect production servers (SSH, Tetragon, Shibboleth), please\n"
                "define your server configuration files:\n"
                "  1. Ingest config : /etc/separ/ingest.yaml (sensor sources & sockets)\n"
                "  2. Signed policy : /etc/separ/policy.yaml (campus domains & subnets)\n"
                "  3. Decoy settings: /etc/separ/decoys.yaml (optional deception)\n\n"
                f"Run '{prog} ingest list' or see /etc/separ/README.md for instructions.\n"
                f"{border}\n",
                file=sys.stderr,
            )
        return serve_forever(
            host=args.host,
            port=args.port,
            workdir=args.workdir,
            hub=hub,
            rootkit_interval_s=args.rootkit_interval,
            decoys=args.decoys,
            ingest=ingest_cfg,
            policy_path=args.policy,
            public_key_path=args.public_key,
            enforce=args.enforce,
        )
    elif args.command == "ingest":
        from .ingest.cli import run as run_ingest

        return run_ingest(args)
    elif args.command == "decoy":
        from .deception.cli import run as run_decoy

        return run_decoy(args)
    elif args.command == "gui":
        from .live import launch_gui

        prog = Path(sys.argv[0]).name if (sys.argv and sys.argv[0]) else "separ"
        if prog not in ("separ", "refmon"):
            prog = "separ"

        try:
            hub = _build_hub(args)
        except ValueError as exc:
            print(f"{prog} gui: {exc}", file=sys.stderr)
            return 2
        ingest_cfg = getattr(args, "ingest", None)
        if not ingest_cfg and Path("/etc/separ/ingest.yaml").is_file():
            ingest_cfg = "/etc/separ/ingest.yaml"
        return launch_gui(
            host=args.host,
            port=args.port,
            workdir=args.workdir,
            hub=hub,
            rootkit_interval_s=args.rootkit_interval,
            open_browser=not args.no_browser,
            decoys=getattr(args, "decoys", None),
            ingest=ingest_cfg,
            policy_path=args.policy,
            public_key_path=args.public_key,
        )
    elif args.command == "health":
        import json

        from .health import check_health, notify_on_change
        from .live import default_live_workdir

        prog = Path(sys.argv[0]).name if (sys.argv and sys.argv[0]) else "separ"
        if prog not in ("separ", "refmon"):
            prog = "separ"

        try:
            hub = _build_hub(args)
        except ValueError as exc:
            print(f"{prog} health: {exc}", file=sys.stderr)
            return 2
        workdir = Path(args.workdir) if args.workdir else default_live_workdir()
        if not args.workdir:
            for sys_workdir in (Path("/var/lib/separ"), Path("/var/lib/refmon")):
                if (
                    not (workdir / "heartbeat.json").exists()
                    and (sys_workdir / "heartbeat.json").is_file()
                ):
                    workdir = sys_workdir
                    break
        now = datetime.now(UTC)
        code, info = check_health(workdir, now)
        if hub.external:
            notify_on_change(workdir, code, info, hub, now)
        if args.as_json:
            print(json.dumps(info, indent=2))
        else:
            prog_label = "Refmon" if prog == "refmon" else "Separ"
            print(f"{prog_label} daemon: {info['status'].upper()} - {info['reason']}")
            if (
                code != 0
                and not args.workdir
                and Path("/var/lib/separ").is_dir()
                and workdir != Path("/var/lib/separ")
            ):
                print(
                    "Tip: System service runs in /var/lib/separ. "
                    f"Try: sudo {prog} health --workdir /var/lib/separ"
                )
            for key in ("pid", "mode", "heartbeat_age_s", "policy_digest"):
                if info.get(key) is not None:
                    print(f"  {key:16} {info[key]}")
            cont = info.get("containment") or {}
            if cont:
                print(f"  {'containment':16} {cont.get('backend')}")
                for action, state in (cont.get("actions") or {}).items():
                    print(f"    {action:20} {state}")
            st = info.get("self_test") or {}
            if st:
                failed = ", ".join(st.get("failed") or []) or "none"
                print(f"  {'self_test':16} passed={st.get('passed')} failed={failed}")
            for prob in info.get("problems", []):
                print(f"  - [{prob.get('severity')}] {prob.get('title')}: {prob.get('subject')}")
        return code
    elif args.command == "lab":
        from .attacklab import main as lab_main

        return lab_main(args)
    elif args.command == "browser-host":
        from .browser_host import Forwarder, serve
        from .live import default_live_workdir

        workdir = Path(args.workdir) if args.workdir else default_live_workdir()
        return serve(sys.stdin.buffer, sys.stdout.buffer, Forwarder(workdir, args.host, args.port))
    elif args.command == "browser-install":
        from .browser_host import install

        home = Path.home()
        if args.launcher_dir:
            launcher_dir = Path(args.launcher_dir)
        elif args.system:
            launcher_dir = Path("/usr/libexec/separ")
            if not launcher_dir.exists() and Path("/usr/libexec/refmon").exists():
                launcher_dir = Path("/usr/libexec/refmon")
        else:
            launcher_dir = home / ".local/share/separ"
            if not launcher_dir.exists() and (home / ".local/share/refmon").exists():
                launcher_dir = home / ".local/share/refmon"
        for path in install(
            home=home,
            launcher_dir=launcher_dir,
            system=args.system,
            workdir=Path(args.workdir) if args.workdir else None,
            port=args.port,
            chromium_ids=args.chromium_ids,
        ):
            print(f"wrote {path}")
    elif args.command == "guard":
        import json
        import shlex

        from .live import send_guard_request

        parts = list(args.cmd_parts)
        if parts and parts[0] == "--":
            parts = parts[1:]
        command_str = parts[0] if len(parts) == 1 else shlex.join(parts)
        if not command_str.strip():
            raise ValueError("guard requires a command after --")
        res = send_guard_request(
            command_str,
            host=args.host,
            port=args.port,
            origin=args.origin,
            role=args.role,
            execute=not args.no_exec,
            workdir=args.workdir,
        )
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            verdict = str(res["decision"]).upper()
            prog = Path(sys.argv[0]).name if (sys.argv and sys.argv[0]) else "separ"
            prog_label = "Refmon" if prog == "refmon" else "Separ"
            print(
                f"[{prog_label} Barrier: {verdict}] mode={res['mode']} "
                f"log_odds={res['log_odds']} nats executed={res['executed']}"
            )
            print(f"  Why: {res['explanation']}")
            if res.get("output"):
                print(res["output"])
        return 1 if res.get("blocked_by_barrier") else 0
    return 0


def _policy_command(args: argparse.Namespace) -> int:
    import json

    from . import admin
    from .config import resolve_policy_paths

    policy, public = resolve_policy_paths(args.policy, args.public_key)
    if args.policy_command == "show":
        info = admin.show(policy, public)
        if args.as_json:
            print(json.dumps(info, indent=2))
        else:
            for key, value in info.items():
                print(f"  {key:16} {value}")
    elif args.policy_command == "sign":
        admin.sign_file(policy, args.key)
        print(f"signed {policy}; run `separ reload` so the daemon adopts it")
    else:
        loaded = admin.set_mode(args.mode, policy, public, args.key)
        print(
            f"{policy}: mode={loaded.policy.mode.value} digest={loaded.digest}; "
            "run `separ reload` so the daemon adopts it"
        )
    return 0


def _reload_command(args: argparse.Namespace) -> int:
    import json
    import os
    import signal
    import urllib.error
    import urllib.request

    from .config import default_workdir, is_root

    workdir = Path(args.workdir) if args.workdir else default_workdir()
    token = (workdir / "api.token").read_text(encoding="utf-8").strip()
    try:
        port = int((workdir / "daemon.port").read_text(encoding="utf-8").strip())
        req = urllib.request.Request(
            f"http://{args.host}:{port}/api/reload",
            data=b"{}",
            headers={"Content-Type": "application/json", "X-Separ-Token": token},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            res = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        beat = json.loads((workdir / "heartbeat.json").read_text(encoding="utf-8"))
        pid = int(beat["pid"])
        if not is_root() and os.stat(workdir / "heartbeat.json").st_uid != os.getuid():
            raise PermissionError("the daemon belongs to another user") from None
        os.kill(pid, signal.SIGHUP)
        print(f"sent SIGHUP to the daemon (pid {pid}); `separ health` shows the mode it adopted")
        return 0
    if not res.get("reloaded"):
        print(f"separ reload: rejected, the last valid policy stays: {res.get('error')}")
        return 1
    print(f"reloaded: mode={res['mode']} digest={res['digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
