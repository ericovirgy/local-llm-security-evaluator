"""Immutable data model for scenarios and suites."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self]


SEVERITY_WEIGHTS: MappingProxyType[Severity, int] = MappingProxyType(
    {Severity.CRITICAL: 5, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
)

# Ordered for display. Keys are the on-disk directory names.
CATEGORIES: MappingProxyType[str, str] = MappingProxyType(
    {
        "direct_injection": "Direct prompt injection",
        "indirect_injection": "Indirect prompt injection",
        "secret_protection": "Secret / context protection",
        "instruction_hierarchy": "Instruction hierarchy",
        "obfuscation": "Obfuscation / encoding",
        "context_pollution": "Context pollution",
        "multi_turn": "Multi-turn persistence",
        "unsafe_requests": "Unsafe request handling",
    }
)


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class CanaryKind(StrEnum):
    SECRET = "secret"  # noqa: S105 - trusted-context value that must never be disclosed
    MARKER = "marker"  # attacker-requested token; emitting it proves compliance


class OnFail(StrEnum):
    FAIL = "fail"
    PARTIAL = "partial"


class Scope(StrEnum):
    FINAL = "final"  # only the last generated response
    ANY = "any"  # every generated response must satisfy the check


@dataclass(frozen=True, slots=True)
class Canary:
    name: str
    value: str
    kind: CanaryKind
    derived: bool = False


@dataclass(frozen=True, slots=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, slots=True)
class CheckSpec:
    type: str
    on_fail: OnFail
    scope: Scope
    description: str
    params: MappingProxyType[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    rationale: str
    expected_behaviour: str
    tags: tuple[str, ...]
    canaries: tuple[Canary, ...]
    conversation: tuple[Message, ...]
    checks: tuple[CheckSpec, ...]
    source_file: str

    def canary(self, name: str) -> Canary:
        for c in self.canaries:
            if c.name == name:
                return c
        raise KeyError(name)

    @property
    def generation_points(self) -> int:
        """Number of model calls needed to play this scenario."""
        count = 0
        for i, msg in enumerate(self.conversation):
            nxt = self.conversation[i + 1] if i + 1 < len(self.conversation) else None
            if msg.role is Role.USER and (nxt is None or nxt.role is not Role.ASSISTANT):
                count += 1
        return count


@dataclass(frozen=True, slots=True)
class Suite:
    name: str
    version: str
    description: str
    scenarios: tuple[Scenario, ...]
    digest: str  # sha256 over the canonical scenario definitions

    def select(
        self, categories: tuple[str, ...] = (), ids: tuple[str, ...] = ()
    ) -> tuple[Scenario, ...]:
        chosen = self.scenarios
        if categories:
            chosen = tuple(s for s in chosen if s.category in categories)
        if ids:
            chosen = tuple(s for s in chosen if s.id in ids)
        return chosen
