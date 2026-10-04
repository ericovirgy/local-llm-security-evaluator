"""Scenario corpus: data model, loading and validation."""

from llmsec.corpus.loader import SuiteError, builtin_suites, load_suite, resolve_suite
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

__all__ = [
    "CATEGORIES",
    "Canary",
    "CanaryKind",
    "CheckSpec",
    "Message",
    "OnFail",
    "Role",
    "Scenario",
    "Scope",
    "Severity",
    "Suite",
    "SuiteError",
    "builtin_suites",
    "load_suite",
    "resolve_suite",
]
