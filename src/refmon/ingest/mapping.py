"""Mapping files: how a line of an external sensor becomes a RawEvent (v2.2, design decision A73).

Refmon cannot ship a kernel sensor for every platform, and the people who run a server are the ones
who may install one (Falco, Tetragon, auditd, the Kubernetes audit log, an identity provider's log).
A mapping file lets them connect such a sensor without writing code:

    name: falco
    format: json                       # json (one object per line) or kv (key=value pairs)
    device: {from: hostname}           # optional default for every rule
    rules:
      - name: shell-spawned
        match:                         # every condition must hold
          rule: {in: ["Terminal shell in container", "Run shell untrusted"]}
          "output_fields[proc.name]": {exists: true}
        event:
          type: exec
          ts: {from: time}
          actor:
            id: "{output_fields[proc.pid]}@{output_fields[container.id]}"
            parent: "{output_fields[proc.ppid]}@{output_fields[container.id]}"
            role: {from: "output_fields[proc.pname]", map: {nginx: web_worker, php-fpm: web_worker},
                   default: other}
            user: {from: "output_fields[user.name]", default: unknown}
          object: {class: command_text, content: {from: "output_fields[proc.cmdline]"}}
          attrs: {program: {from: "output_fields[proc.name]"}}

Paths: `a.b.c` walks nested objects; `a[b.c]` reads the literal key `b.c` (Falco and journald use
dotted key names); `a.0` indexes a list. Values: a literal, a template string with `{path}` parts,
or `{from: path}` with optional `map`, `default`, `regex` + `group`, `as` (int, float, bool, str),
`lower`, `basename`. The first rule whose `match` holds builds the event; a line no rule matches is
counted and dropped.

Privacy (CLAUDE.md Part A): the mapping hands raw values (command lines, paths, addresses) to
Observe in memory and nothing else. It never logs, stores or prints them; counters and errors are
fixed phrases. Identifiers (actor id, device, user) are cleaned to the Identifier alphabet.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..schemas import EVENT_ATTR_KEYS, EventType, RawEvent

_ID_BAD = re.compile(r"[^A-Za-z0-9_.:@-]")
_TEMPLATE = re.compile(r"\{([^{}]+)\}")
_MISSING = object()


class MappingError(ValueError):
    """A mapping file that cannot work (rejected when it is loaded, never at run time)."""


def split_path(path: str) -> list[str]:
    """`a.b[c.d].0` -> ['a', 'b', 'c.d', '0']."""
    out: list[str] = []
    buf = ""
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "[":
            end = path.find("]", i)
            if end < 0:
                raise MappingError(f"unclosed [ in path {path!r}")
            if buf:
                out.append(buf)
                buf = ""
            out.append(path[i + 1 : end])
            i = end + 1
            if i < len(path) and path[i] == ".":
                i += 1
            continue
        if ch == ".":
            if buf:
                out.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if buf:
        out.append(buf)
    if not out:
        raise MappingError("empty path")
    return out


def lookup(record: Any, path: str) -> Any:
    cur = record
    for part in split_path(path):
        if isinstance(cur, dict):
            cur = cur.get(part, _MISSING)
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            cur = cur[idx] if -len(cur) <= idx < len(cur) else _MISSING
        else:
            return _MISSING
        if cur is _MISSING:
            return _MISSING
    return cur


def clean_identifier(value: Any, fallback: str = "unknown") -> str:
    text = _ID_BAD.sub("_", str(value)).strip("_")[:64]
    return text or fallback


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    equals: Any = None
    in_: list[Any] | None = Field(default=None, alias="in")
    regex: str | None = None
    exists: bool | None = None

    @field_validator("regex")
    @classmethod
    def _compiles(cls, value):
        if value is not None:
            re.compile(value)
        return value

    def holds(self, value: Any) -> bool:
        present = value is not _MISSING and value is not None
        if self.exists is not None and present != self.exists:
            return False
        if not present:
            return self.exists is False
        if self.equals is not None and value != self.equals:
            return False
        if self.in_ is not None and value not in self.in_:
            return False
        return self.regex is None or bool(re.search(self.regex, str(value)))


def _condition(spec: Any) -> Condition:
    if isinstance(spec, dict):
        return Condition.model_validate(spec)
    if isinstance(spec, list):
        return Condition.model_validate({"in": spec})
    return Condition(equals=spec)


class ValueSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: str | None = Field(default=None, alias="from")
    const: Any = None
    template: str | None = None
    map: dict[str, Any] | str | None = None  # a table, or the name of one of the mapping's `tables`
    default: Any = None
    regex: str | None = None
    group: int | str = 1
    as_: Literal["str", "int", "float", "bool"] | None = Field(default=None, alias="as")
    lower: bool = False
    basename: bool = False
    strip_version: bool = False  # php-fpm8.2 -> php-fpm, python3.11 -> python
    prefix: str = ""  # put in front of a found value, e.g. "acct:" for an account actor
    # in a list of objects, the one whose `key` equals `equals`, then its `take` (M365 Parameters)
    find: dict[str, str] | None = None
    first: list[Any] | None = None  # alternatives: the first one that is not missing
    classify: list[dict[str, Any]] | None = None  # [{regex: ..., value: ...}]: first match wins

    @field_validator("classify")
    @classmethod
    def _classify_compiles(cls, value):
        for item in value or ():
            if set(item) != {"regex", "value"}:
                raise ValueError("a classify entry has exactly `regex` and `value`")
            re.compile(item["regex"])
        return value

    @field_validator("regex")
    @classmethod
    def _compiles(cls, value):
        if value is not None:
            re.compile(value)
        return value

    def evaluate(self, record: Any, tables: dict | None = None) -> Any:
        if self.first is not None:
            value = _MISSING
            for alt in self.first:
                got = value_spec(alt).evaluate(record, tables)
                if got is not None:
                    value = got
                    break
        elif self.const is not None:
            value = self.const
        elif self.template is not None:
            value = render(self.template, record)
        elif self.from_ is not None:
            value = lookup(record, self.from_)
        else:
            value = _MISSING
        if self.find is not None:
            value = _find(value, self.find)
        if value is not _MISSING and value is not None and self.regex is not None:
            m = re.search(self.regex, str(value))
            value = m.group(self.group) if m else _MISSING
        if value is _MISSING or value is None or value == "":
            return self.default
        if self.basename:
            value = os.path.basename(str(value).rstrip("/"))
        if self.strip_version:
            value = re.sub(r"[-_.]?\d[\d.]*$", "", str(value)) or str(value)
        if self.lower:
            value = str(value).lower()
        if self.classify is not None:
            text = str(value)
            value = next(
                (c["value"] for c in self.classify if re.search(c["regex"], text)), self.default
            )
            if value is None:
                return None
        if self.map is not None:
            table = (tables or {}).get(self.map, {}) if isinstance(self.map, str) else self.map
            value = table.get(str(value), self.default)
            if value is None:
                return None
        if self.prefix:
            value = f"{self.prefix}{value}"
        return _cast(value, self.as_)


def _find(items: Any, spec: dict[str, str]) -> Any:
    if not isinstance(items, list):
        return _MISSING
    for item in items:
        if isinstance(item, dict) and str(item.get(spec["key"], "")) == spec["equals"]:
            return item.get(spec["take"], _MISSING)
    return _MISSING


def _cast(value: Any, as_: str | None) -> Any:
    if as_ is None:
        return value
    if as_ == "str":
        return str(value)
    if as_ == "int":
        return int(float(value))
    if as_ == "float":
        return float(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)


def render(template: str, record: Any) -> Any:
    """`"{a}@{b}"` -> the values filled in; a template that names a missing path is missing."""
    missing = False

    def fill(m: re.Match) -> str:
        nonlocal missing
        value = lookup(record, m.group(1).strip())
        if value is _MISSING or value is None:
            missing = True
            return ""
        return str(value)

    out = _TEMPLATE.sub(fill, template)
    return _MISSING if missing else out


def value_spec(spec: Any) -> ValueSpec:
    if isinstance(spec, dict):
        return ValueSpec.model_validate(spec)
    if isinstance(spec, str) and _TEMPLATE.search(spec):
        return ValueSpec(template=spec)
    return ValueSpec(const=spec)


class ActorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Any
    role: Any
    user: Any = "unknown"
    parent: Any = None
    interactive: Any = False
    # the actor's real process id, where the sensor gives one: only the enforcer uses it
    pid: Any = None


class ObjectSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    class_: Any = Field(alias="class")
    content: Any = None


class EventSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: EventType
    ts: Any = None  # a path to an ISO 8601 time, a number of seconds (or ns) since 1970; else now
    device: Any = None
    actor: ActorSpec
    object: ObjectSpec
    attrs: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    match: dict[str, Any] = Field(default_factory=dict)
    event: EventSpec


class Mapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    description: str = ""
    format: Literal["json", "kv", "delimited"] = "json"
    delimiter: str = "|"  # delimited only
    fields: list[str] = Field(default_factory=list)  # delimited only: the names of the columns
    device: Any = None
    # what this sensor supplies, as heartbeat capability names (degraded protection, Phase 6)
    provides: list[str] = Field(default_factory=list)
    # named lookup tables, used as `map: <name>` (e.g. one role table for every rule)
    tables: dict[str, dict[str, Any]] = Field(default_factory=dict)
    rules: list[Rule]

    @field_validator("rules")
    @classmethod
    def _non_empty(cls, value):
        if not value:
            raise ValueError("a mapping needs at least one rule")
        return value


def parse_ts(value: Any) -> datetime:
    if value is None or value is _MISSING:
        return datetime.now(UTC)
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and value.replace(".", "", 1).isdigit()
    ):
        number = float(value)
        if number > 1e17:  # nanoseconds (Tetragon, journald __REALTIME_TIMESTAMP is microseconds)
            number /= 1e9
        elif number > 1e14:
            number /= 1e6
        elif number > 1e11:
            number /= 1e3
        return datetime.fromtimestamp(number, UTC)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    m = re.match(r"^(.*\.\d{6})\d+([+-]\d\d:\d\d)?$", text)  # nanosecond precision: cut to micro
    if m:
        text = m.group(1) + (m.group(2) or "")
    ts = datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


_KV = re.compile(r'([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_line(line: str, fmt: str, *, delimiter: str = "|", fields: list[str] = ()) -> Any:
    import json

    if fmt == "json":
        return json.loads(line)
    if fmt == "delimited":
        values = line.split(delimiter)
        out = {name: value for name, value in zip(fields, values, strict=False) if name}
        out["_line"] = line
        return out
    out = {"_line": line}  # the whole line: a time or a prefix outside the key=value pairs
    for key, raw in _KV.findall(line):
        if raw.startswith('"'):
            out[key] = raw[1:-1].replace('\\"', '"')
        else:
            out[key] = raw.rstrip(",;")  # Keycloak: "type=LOGIN, realmId=..."
    return out


class Mapper:
    """A loaded mapping: `map(line)` -> (RawEvent | None, outcome). Outcomes are counted, never
    logged with their content: `mapped`, `unmatched`, `unparsable`, `invalid`."""

    def __init__(self, mapping: Mapping, *, extra_roles: tuple[str, ...] = ()) -> None:
        self.mapping = mapping
        self.extra_roles = extra_roles
        self._seq = 0
        self._compiled = []
        for rule in mapping.rules:
            conds = [(path, _condition(spec)) for path, spec in rule.match.items()]
            for path, _ in conds:
                split_path(path)
            ev = rule.event
            attrs = {k: value_spec(v) for k, v in ev.attrs.items()}
            self._compiled.append((rule, conds, attrs))
        self.device = value_spec(mapping.device) if mapping.device is not None else None
        unknown = sorted(_table_names(mapping) - set(mapping.tables))
        if unknown:
            raise MappingError(f"mapping {mapping.name} uses unknown tables: {unknown}")

    def map(self, line: str) -> tuple[RawEvent | None, str]:
        line = line.strip()
        if not line:
            return None, "unmatched"
        try:
            m = self.mapping
            record = parse_line(line, m.format, delimiter=m.delimiter, fields=m.fields)
        except ValueError:
            return None, "unparsable"
        if not isinstance(record, dict):
            return None, "unparsable"
        for rule, conds, attrs in self._compiled:
            if all(cond.holds(lookup(record, path)) for path, cond in conds):
                return self._build(rule, attrs, record)
        return None, "unmatched"

    def _build(self, rule: Rule, attrs: dict, record: dict) -> tuple[RawEvent | None, str]:
        ev = rule.event
        tb = self.mapping.tables
        try:
            a = ev.actor
            actor = {
                "id": clean_identifier(value_spec(a.id).evaluate(record, tb)),
                "role": value_spec(a.role).evaluate(record, tb) or "other",
                "user": clean_identifier(value_spec(a.user).evaluate(record, tb)),
                "interactive": bool(
                    _cast(value_spec(a.interactive).evaluate(record, tb) or False, "bool")
                ),
            }
            parent = value_spec(a.parent).evaluate(record, tb) if a.parent is not None else None
            if parent not in (None, ""):
                actor["parent"] = clean_identifier(parent)
            pid = value_spec(a.pid).evaluate(record, tb) if a.pid is not None else None
            pid = int(pid) if pid not in (None, "") and str(pid).isdigit() else None
            content = (
                value_spec(ev.object.content).evaluate(record, tb) if ev.object.content else None
            )
            device_spec = value_spec(ev.device) if ev.device is not None else self.device
            device = device_spec.evaluate(record, tb) if device_spec is not None else None
            values = {}
            for key, spec in attrs.items():
                value = spec.evaluate(record, tb)
                if value is None:
                    continue
                if isinstance(value, (bool, int, float)):
                    values[key] = value
                elif key in EVENT_ATTR_KEYS:  # kept after Observe: a short identifier (C2)
                    values[key] = clean_identifier(value)
                else:  # a raw attribute Observe consumes and drops
                    values[key] = str(value)[:256]
            ts = parse_ts(value_spec(ev.ts).evaluate(record, tb) if ev.ts is not None else None)
            self._seq += 1
            event = RawEvent.model_validate(
                {
                    "event_id": f"in-{self.mapping.name[:40]}-{self._seq:08d}",
                    "ts": ts,
                    "device": clean_identifier(device or "ingest-host"),
                    "type": ev.type,
                    "actor": actor,
                    "object": {
                        "class": clean_identifier(
                            value_spec(ev.object.class_).evaluate(record, tb)
                        ),
                        "content": None if content is None else str(content)[:65536],
                    },
                    "attrs": values,
                    "pid": pid if pid else None,
                },
                context={"extra_roles": self.extra_roles},
            )
        except (ValueError, TypeError, OverflowError):
            return None, "invalid"
        return event, "mapped"


def load_mapping(path, *, extra_roles: tuple[str, ...] = ()) -> Mapper:
    from ..yamlio import read_document

    try:
        mapping = Mapping.model_validate(read_document(path))
    except ValueError as exc:
        raise MappingError(f"{path}: {exc}") from exc
    return Mapper(mapping, extra_roles=extra_roles)


def _table_names(node: Any) -> set[str]:
    """Every `map: <name>` in a mapping (tables named by string)."""
    found: set[str] = set()
    if isinstance(node, BaseModel):
        node = node.model_dump(by_alias=True)
    if isinstance(node, dict):
        if isinstance(node.get("map"), str):
            found.add(node["map"])
        for k, v in node.items():
            if k != "tables":
                found |= _table_names(v)
    elif isinstance(node, list):
        for v in node:
            found |= _table_names(v)
    return found
