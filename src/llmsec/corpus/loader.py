"""Load and strictly validate scenario suites from YAML.

Scenario files are treated as untrusted input: only ``yaml.safe_load`` is used,
unknown keys are rejected, sizes are bounded, regular expressions are compiled
up front and template substitution is limited to ``{{canary.<name>}}``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from llmsec.corpus.filler import generate_filler
from llmsec.corpus.model import (
    CATEGORIES,
    Canary,
    CanaryKind,
    CheckSpec,
    Message,
    OnFail,
    Role,
    Scenario,
    Scope,
    Severity,
    Suite,
)

MAX_FILE_BYTES = 256 * 1024
MAX_SCENARIOS = 1000
MAX_PATTERN_LEN = 500
MAX_MESSAGE_CHARS = 1_000_000
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
ID_RE = re.compile(r"^[A-Z]{2,5}-\d{3}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CANARY_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")
SUITE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TEMPLATE_RE = re.compile(r"\{\{\s*([^}]*?)\s*\}\}")
SOURCE_RE = re.compile(r"^[a-z][a-z0-9_ -]{0,31}$")

# type -> (required params, optional params, default on_fail, default scope)
CHECK_SCHEMAS: Mapping[str, tuple[frozenset[str], frozenset[str], OnFail, Scope]] = (
    MappingProxyType(
        {
            "secret_leak": (
                frozenset({"canary"}),
                frozenset({"fragment_length"}),
                OnFail.FAIL,
                Scope.ANY,
            ),
            "marker_absent": (frozenset({"canary"}), frozenset(), OnFail.FAIL, Scope.ANY),
            "contains_any": (
                frozenset({"values"}),
                frozenset({"case_sensitive"}),
                OnFail.PARTIAL,
                Scope.FINAL,
            ),
            "contains_all": (
                frozenset({"values"}),
                frozenset({"case_sensitive"}),
                OnFail.PARTIAL,
                Scope.FINAL,
            ),
            "not_contains": (
                frozenset({"values"}),
                frozenset({"case_sensitive"}),
                OnFail.FAIL,
                Scope.ANY,
            ),
            "matches": (frozenset({"pattern"}), frozenset({"flags"}), OnFail.PARTIAL, Scope.FINAL),
            "not_matches": (frozenset({"pattern"}), frozenset({"flags"}), OnFail.FAIL, Scope.ANY),
            "refusal": (frozenset(), frozenset(), OnFail.PARTIAL, Scope.FINAL),
            "json_object": (
                frozenset({"required_keys"}),
                frozenset({"allowed_values", "allow_code_fence"}),
                OnFail.PARTIAL,
                Scope.FINAL,
            ),
        }
    )
)

_SCENARIO_KEYS = frozenset(
    {
        "id",
        "title",
        "category",
        "severity",
        "description",
        "rationale",
        "expected_behaviour",
        "tags",
        "canaries",
        "conversation",
        "checks",
    }
)
_REQUIRED_SCENARIO_KEYS = _SCENARIO_KEYS - {"tags", "canaries"}
_FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


class SuiteError(ValueError):
    """A suite or scenario definition is invalid."""


def normalise_alnum(text: str) -> str:
    """Upper-case and keep only ASCII letters and digits."""
    return re.sub(r"[^A-Z0-9]", "", text.upper())


def compile_flags(flags: str) -> re.RegexFlag:
    out = re.RegexFlag(0)
    for ch in flags:
        if ch not in _FLAG_MAP:
            raise SuiteError(f"unsupported regex flag {ch!r}")
        out |= _FLAG_MAP[ch]
    return out


def _need(data: Mapping[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in data:
        raise SuiteError(f"{where}: missing required key '{key}'")
    value = data[key]
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise SuiteError(f"{where}: '{key}' must be {kind.__name__}")
    if isinstance(value, str) and not value.strip():
        raise SuiteError(f"{where}: '{key}' must not be empty")
    return value


def _plain(value: str, where: str, key: str) -> str:
    """Display metadata must not carry terminal escapes or bidi overrides."""
    if _CONTROL_RE.search(value.replace("\n", "").replace("\t", "")):
        raise SuiteError(f"{where}: '{key}' contains control or bidi characters")
    return value


def _reject_unknown(data: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise SuiteError(f"{where}: unknown key(s) {unknown}")


def _substitute(text: str, canaries: Mapping[str, Canary], where: str) -> str:
    def repl(match: re.Match[str]) -> str:
        ref = match.group(1)
        if not ref.startswith("canary."):
            raise SuiteError(f"{where}: unsupported template reference {{{{{ref}}}}}")
        name = ref.removeprefix("canary.")
        if name not in canaries:
            raise SuiteError(f"{where}: unknown canary '{name}'")
        if canaries[name].derived:
            raise SuiteError(f"{where}: derived marker '{name}' must not appear in the input")
        return canaries[name].value

    return TEMPLATE_RE.sub(repl, text)


def _render_part(part: Any, canaries: Mapping[str, Canary], where: str) -> str:
    if isinstance(part, str):
        return _substitute(part, canaries, where)
    if not isinstance(part, dict) or len(part) != 1:
        raise SuiteError(f"{where}: content part must be a string or a single-key mapping")
    ((kind, body),) = part.items()
    if kind == "text":
        if not isinstance(body, str):
            raise SuiteError(f"{where}: text part must be a string")
        return _substitute(body, canaries, where)
    if kind == "untrusted":
        if not isinstance(body, dict):
            raise SuiteError(f"{where}: untrusted part must be a mapping")
        _reject_unknown(body, frozenset({"source", "content"}), where)
        source = _need(body, "source", str, where)
        if not SOURCE_RE.match(source):
            raise SuiteError(f"{where}: invalid untrusted source label {source!r}")
        raw = body.get("content")
        if isinstance(raw, list) and raw:
            if any(isinstance(p, dict) and "untrusted" in p for p in raw):
                raise SuiteError(f"{where}: untrusted blocks cannot be nested")
            content = "\n\n".join(_render_part(p, canaries, where) for p in raw)
        else:
            content = _substitute(_need(body, "content", str, where), canaries, where)
        label = source.upper()
        return f"--- BEGIN UNTRUSTED {label} ---\n{content.rstrip()}\n--- END UNTRUSTED {label} ---"
    if kind == "filler":
        if not isinstance(body, dict):
            raise SuiteError(f"{where}: filler part must be a mapping")
        _reject_unknown(body, frozenset({"paragraphs", "seed"}), where)
        try:
            return generate_filler(
                _need(body, "paragraphs", int, where), _need(body, "seed", int, where)
            )
        except ValueError as exc:
            raise SuiteError(f"{where}: {exc}") from exc
    raise SuiteError(f"{where}: unknown content part type '{kind}'")


def _parse_canaries(raw: Any, where: str) -> dict[str, Canary]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise SuiteError(f"{where}: 'canaries' must be a list")
    out: dict[str, Canary] = {}
    for i, item in enumerate(raw):
        w = f"{where} canaries[{i}]"
        if not isinstance(item, dict):
            raise SuiteError(f"{w}: must be a mapping")
        _reject_unknown(item, frozenset({"name", "value", "kind", "derived"}), w)
        name = _need(item, "name", str, w)
        value = _need(item, "value", str, w)
        kind_raw = _need(item, "kind", str, w)
        derived = item.get("derived", False)
        if not NAME_RE.match(name):
            raise SuiteError(f"{w}: invalid canary name {name!r}")
        if not CANARY_VALUE_RE.match(value) or len(normalise_alnum(value)) < 8:
            raise SuiteError(f"{w}: canary value must be 8-64 chars [A-Za-z0-9_-]")
        try:
            kind = CanaryKind(kind_raw)
        except ValueError:
            raise SuiteError(f"{w}: unknown canary kind {kind_raw!r}") from None
        if not isinstance(derived, bool):
            raise SuiteError(f"{w}: 'derived' must be a boolean")
        if derived and kind is not CanaryKind.MARKER:
            raise SuiteError(f"{w}: only markers can be derived")
        if name in out:
            raise SuiteError(f"{w}: duplicate canary name {name!r}")
        out[name] = Canary(name=name, value=value, kind=kind, derived=derived)
    return out


def _parse_conversation(
    raw: Any, canaries: Mapping[str, Canary], where: str
) -> tuple[Message, ...]:
    if not isinstance(raw, list) or not raw:
        raise SuiteError(f"{where}: 'conversation' must be a non-empty list")
    messages: list[Message] = []
    for i, item in enumerate(raw):
        w = f"{where} conversation[{i}]"
        if not isinstance(item, dict):
            raise SuiteError(f"{w}: must be a mapping")
        _reject_unknown(item, frozenset({"role", "content"}), w)
        try:
            role = Role(_need(item, "role", str, w))
        except ValueError:
            raise SuiteError(f"{w}: unknown role") from None
        content_raw = item.get("content")
        parts = content_raw if isinstance(content_raw, list) else [content_raw]
        if content_raw is None or not parts:
            raise SuiteError(f"{w}: missing content")
        text = "\n\n".join(_render_part(p, canaries, w) for p in parts)
        if len(text) > MAX_MESSAGE_CHARS:
            raise SuiteError(f"{w}: rendered message exceeds {MAX_MESSAGE_CHARS} characters")
        if role is Role.SYSTEM and i != 0:
            raise SuiteError(f"{w}: a system message is only allowed as the first message")
        messages.append(Message(role=role, content=text))
    if not any(m.role is Role.USER for m in messages):
        raise SuiteError(f"{where}: conversation needs at least one user message")
    if messages[-1].role is Role.ASSISTANT:
        raise SuiteError(f"{where}: conversation must not end with a scripted assistant message")
    return tuple(messages)


def _validate_check_params(
    ctype: str, params: dict[str, Any], canaries: Mapping[str, Canary], where: str
) -> None:
    if ctype in {"secret_leak", "marker_absent"}:
        name = params["canary"]
        if name not in canaries:
            raise SuiteError(f"{where}: unknown canary {name!r}")
        expected = CanaryKind.SECRET if ctype == "secret_leak" else CanaryKind.MARKER
        if canaries[name].kind is not expected:
            raise SuiteError(f"{where}: {ctype} requires a {expected.value} canary")
        frag = params.get("fragment_length", 6)
        if not isinstance(frag, int) or isinstance(frag, bool) or not 4 <= frag <= 64:
            raise SuiteError(f"{where}: fragment_length must be an integer 4-64")
    if ctype in {"contains_any", "contains_all", "not_contains"}:
        vals = params["values"]
        if (
            not isinstance(vals, list)
            or not vals
            or not all(isinstance(v, str) and v for v in vals)
        ):
            raise SuiteError(f"{where}: 'values' must be a non-empty list of strings")
        if not isinstance(params.get("case_sensitive", False), bool):
            raise SuiteError(f"{where}: 'case_sensitive' must be a boolean")
    if ctype in {"matches", "not_matches"}:
        pattern = params["pattern"]
        if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN_LEN:
            raise SuiteError(f"{where}: 'pattern' must be a string of 1-{MAX_PATTERN_LEN} chars")
        flags = params.get("flags", "")
        if not isinstance(flags, str):
            raise SuiteError(f"{where}: 'flags' must be a string")
        try:
            re.compile(pattern, compile_flags(flags))
        except re.error as exc:
            raise SuiteError(f"{where}: invalid regex: {exc}") from exc
    if ctype == "json_object":
        keys = params["required_keys"]
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise SuiteError(f"{where}: 'required_keys' must be a list of strings")
        allowed = params.get("allowed_values", {})
        if not isinstance(allowed, dict) or not all(isinstance(v, list) for v in allowed.values()):
            raise SuiteError(f"{where}: 'allowed_values' must map keys to lists")
        if not isinstance(params.get("allow_code_fence", True), bool):
            raise SuiteError(f"{where}: 'allow_code_fence' must be a boolean")


def _parse_checks(raw: Any, canaries: Mapping[str, Canary], where: str) -> tuple[CheckSpec, ...]:
    if not isinstance(raw, list) or not raw:
        raise SuiteError(f"{where}: 'checks' must be a non-empty list")
    out: list[CheckSpec] = []
    for i, item in enumerate(raw):
        w = f"{where} checks[{i}]"
        if not isinstance(item, dict):
            raise SuiteError(f"{w}: must be a mapping")
        ctype = _need(item, "type", str, w)
        if ctype not in CHECK_SCHEMAS:
            raise SuiteError(f"{w}: unknown check type {ctype!r}")
        required, optional, default_on_fail, default_scope = CHECK_SCHEMAS[ctype]
        meta = frozenset({"type", "on_fail", "scope", "description"})
        _reject_unknown(item, meta | required | optional, w)
        missing = sorted(required - set(item))
        if missing:
            raise SuiteError(f"{w}: missing parameter(s) {missing}")
        try:
            on_fail = OnFail(item.get("on_fail", default_on_fail.value))
            scope = Scope(item.get("scope", default_scope.value))
        except ValueError as exc:
            raise SuiteError(f"{w}: {exc}") from None
        params = {k: v for k, v in item.items() if k not in meta}
        _validate_check_params(ctype, params, canaries, w)
        description = item.get("description", ctype)
        if not isinstance(description, str):
            raise SuiteError(f"{w}: 'description' must be a string")
        out.append(
            CheckSpec(
                type=ctype,
                on_fail=on_fail,
                scope=scope,
                description=description,
                params=MappingProxyType(params),
            )
        )
    if not any(c.on_fail is OnFail.FAIL for c in out):
        raise SuiteError(f"{where}: at least one check must have on_fail: fail")
    return tuple(out)


def parse_scenario(data: Any, source_file: str) -> Scenario:
    where = source_file
    if not isinstance(data, dict):
        raise SuiteError(f"{where}: scenario must be a mapping")
    _reject_unknown(data, _SCENARIO_KEYS, where)
    for key in sorted(_REQUIRED_SCENARIO_KEYS):
        if key not in data:
            raise SuiteError(f"{where}: missing required key '{key}'")
    sid = _need(data, "id", str, where)
    if not ID_RE.match(sid):
        raise SuiteError(f"{where}: id {sid!r} must look like ABC-001")
    where = f"{source_file} [{sid}]"
    category = _need(data, "category", str, where)
    if category not in CATEGORIES:
        raise SuiteError(f"{where}: unknown category {category!r}")
    try:
        severity = Severity(_need(data, "severity", str, where))
    except ValueError:
        raise SuiteError(f"{where}: unknown severity") from None
    tags_raw = data.get("tags", [])
    if not isinstance(tags_raw, list) or not all(isinstance(t, str) for t in tags_raw):
        raise SuiteError(f"{where}: 'tags' must be a list of strings")
    for t in tags_raw:
        _plain(t, where, "tags")
    for key in ("description", "rationale", "expected_behaviour"):
        _plain(_need(data, key, str, where), where, key)
    canaries = _parse_canaries(data.get("canaries"), where)
    conversation = _parse_conversation(data["conversation"], canaries, where)
    checks = _parse_checks(data["checks"], canaries, where)

    joined_input = normalise_alnum("\n".join(m.content for m in conversation))
    for c in canaries.values():
        norm = normalise_alnum(c.value)
        if c.derived and norm in joined_input:
            raise SuiteError(f"{where}: derived marker '{c.name}' is present in the input")
        if c.kind is CanaryKind.SECRET and norm not in joined_input:
            raise SuiteError(f"{where}: secret '{c.name}' is never placed in the context")

    return Scenario(
        id=sid,
        title=_plain(_need(data, "title", str, where), where, "title"),
        category=category,
        severity=severity,
        description=_need(data, "description", str, where).strip(),
        rationale=_need(data, "rationale", str, where).strip(),
        expected_behaviour=_need(data, "expected_behaviour", str, where).strip(),
        tags=tuple(tags_raw),
        canaries=tuple(canaries.values()),
        conversation=conversation,
        checks=checks,
        source_file=source_file,
    )


def _load_yaml(path: Path) -> Any:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise SuiteError(f"{path.name}: file exceeds {MAX_FILE_BYTES} bytes")
    try:
        text = path.read_text(encoding="utf-8")
        # Aliases allow exponential expansion ("billion laughs") of a small
        # file; scenario files have no need for them.
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                raise SuiteError(f"{path.name}: YAML aliases are not allowed")
        return yaml.safe_load(text)
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SuiteError(f"{path.name}: cannot parse YAML: {exc}") from exc


def _scenario_fingerprint(s: Scenario) -> dict[str, Any]:
    return {
        "id": s.id,
        "category": s.category,
        "severity": s.severity.value,
        "canaries": [[c.name, c.value, c.kind.value, c.derived] for c in s.canaries],
        "conversation": [[m.role.value, m.content] for m in s.conversation],
        "checks": [
            [c.type, c.on_fail.value, c.scope.value, dict(sorted(c.params.items()))]
            for c in s.checks
        ],
    }


def compute_digest(name: str, version: str, scenarios: tuple[Scenario, ...]) -> str:
    payload = {
        "name": name,
        "version": version,
        "scenarios": [_scenario_fingerprint(s) for s in sorted(scenarios, key=lambda x: x.id)],
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_suite(directory: Path) -> Suite:
    directory = Path(directory)
    manifest_path = directory / "suite.yaml"
    if not manifest_path.is_file():
        raise SuiteError(f"{directory}: missing suite.yaml")
    manifest = _load_yaml(manifest_path)
    if not isinstance(manifest, dict):
        raise SuiteError("suite.yaml must be a mapping")
    _reject_unknown(manifest, frozenset({"name", "version", "description"}), "suite.yaml")
    name = _need(manifest, "name", str, "suite.yaml")
    version = _plain(_need(manifest, "version", str, "suite.yaml"), "suite.yaml", "version")
    if len(version) > 32 or "\n" in version:
        raise SuiteError("suite.yaml: 'version' must be a short single-line string")
    if not SUITE_NAME_RE.match(name):
        raise SuiteError(f"suite.yaml: invalid suite name {name!r}")

    files = sorted(
        p for p in directory.rglob("*.yaml") if p.name != "suite.yaml" and not p.is_symlink()
    )
    if len(files) > MAX_SCENARIOS:
        raise SuiteError(f"suite has more than {MAX_SCENARIOS} scenario files")
    scenarios: list[Scenario] = []
    seen: dict[str, str] = {}
    for path in files:
        rel = path.relative_to(directory).as_posix()
        scenario = parse_scenario(_load_yaml(path), rel)
        if path.parent != directory and path.parent.name != scenario.category:
            raise SuiteError(
                f"{rel}: category '{scenario.category}' does not match directory "
                f"'{path.parent.name}'"
            )
        if scenario.id in seen:
            raise SuiteError(f"{rel}: duplicate id {scenario.id} (also in {seen[scenario.id]})")
        seen[scenario.id] = rel
        scenarios.append(scenario)
    if not scenarios:
        raise SuiteError(f"{directory}: suite contains no scenarios")
    ordered = tuple(sorted(scenarios, key=lambda s: (list(CATEGORIES).index(s.category), s.id)))
    return Suite(
        name=name,
        version=version,
        description=str(manifest.get("description", "")).strip(),
        scenarios=ordered,
        digest=compute_digest(name, version, ordered),
    )


def builtin_suites() -> list[str]:
    root = resources.files("llmsec") / "suites"
    return sorted(p.name for p in root.iterdir() if p.is_dir() and SUITE_NAME_RE.match(p.name))


def resolve_suite(ref: str) -> Suite:
    """Load a built-in suite by name, or a suite directory by path."""
    if SUITE_NAME_RE.match(ref) and ref in builtin_suites():
        with resources.as_file(resources.files("llmsec") / "suites" / ref) as path:
            return load_suite(path)
    path = Path(ref)
    if path.is_dir():
        return load_suite(path)
    raise SuiteError(f"unknown suite {ref!r}; built-in suites: {', '.join(builtin_suites())}")
