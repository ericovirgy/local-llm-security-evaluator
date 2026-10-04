"""Helpers for validating the shape of endpoint responses."""

from __future__ import annotations

from typing import Any

from llmsec.adapters.base import AdapterError


def get_str(obj: Any, key: str, where: str, optional: bool = False) -> str | None:
    if not isinstance(obj, dict):
        raise AdapterError(f"{where}: expected an object")
    value = obj.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise AdapterError(f"{where}: field '{key}' missing or not a string")
    return value


def get_int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def opt_str(obj: Any, key: str) -> str | None:
    if isinstance(obj, dict):
        value = obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None
