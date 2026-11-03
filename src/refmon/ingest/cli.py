"""`refmon ingest ...`: help for the admins who connect a sensor (v2.2).

    refmon ingest list                                   the mapping templates shipped with Refmon
    refmon ingest check MAPPING --input SAMPLE [--judge] dry-run a mapping on sample sensor output

`check` never prints raw content: per line it shows the outcome, the event type, role, actor id,
the attribute keys and the length of the content, so a mapping can be tuned on real sensor output
without the output ending up in a terminal log. `--judge` also replays the mapped events through a
fresh pipeline with the reference policy and prints each story's decision and failed questions.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .mapping import MappingError, load_mapping

TEMPLATES = Path(__file__).parent / "mappings"


def add_parser(sub) -> None:
    ing = sub.add_parser("ingest", help="connect external sensors through mapping files")
    isub = ing.add_subparsers(dest="ingest_command", required=True)
    isub.add_parser("list")
    chk = isub.add_parser("check")
    chk.add_argument("mapping")
    chk.add_argument("--input", required=True, help="a file of sensor output, one record per line")
    chk.add_argument("--judge", action="store_true")
    chk.add_argument("--policy", default=None, help="a signed policy (default: the reference one)")
    chk.add_argument("--public-key", default=None)


def _policy(args):
    from ..policy import default_policy
    from ..policy_io import load_policy

    if args.policy:
        if not args.public_key:
            raise ValueError("--policy needs --public-key")
        return load_policy(args.policy, [Path(args.public_key).read_text().strip()])
    return default_policy()


def run(args: argparse.Namespace) -> int:
    if args.ingest_command == "list":
        for path in sorted(TEMPLATES.glob("*.yaml")):
            first = path.read_text(encoding="utf-8").splitlines()[0].lstrip("# ")
            print(f"{path}\n    {first}")
        return 0
    policy = _policy(args)
    try:
        mapper = load_mapping(args.mapping, extra_roles=tuple(policy.extra_roles))
    except MappingError as exc:
        print(f"refmon ingest: {exc}")
        return 2
    outcomes: Counter[str] = Counter()
    events = []
    with open(args.input, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            event, outcome = mapper.map(line)
            outcomes[outcome] += 1
            if event is None:
                print(f"line {n}: {outcome}")
                continue
            events.append(event)
            content = event.object.content
            size = f"content {len(content)} chars" if content is not None else "no content"
            print(f"line {n}: {event.type.value} by {event.actor.role} ({event.actor.id}), "
                  f"object {event.object.class_}, {size}, attrs {sorted(event.attrs)}")  # fmt: skip
    print("summary: " + ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
    if args.judge and events:
        from ..pipeline import Pipeline

        pipe = Pipeline(policy)
        for event in events:
            pipe.process(event)
        for sid, j in pipe.judgements().items():
            failed = [q for q, f in j.failed.items() if f]
            print(f"story {sid}: {j.decision.value} (failed: {', '.join(failed) or 'none'}"
                  f"{', override ' + j.override.value if j.override else ''})")  # fmt: skip
    return 0 if outcomes.get("mapped") else 1
