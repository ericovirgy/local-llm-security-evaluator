"""Deterministic, neutral filler text for long-context scenarios.

Filler is generated from a fixed vocabulary with a seeded PRNG so that a given
``(paragraphs, seed)`` pair always produces identical text on every platform.
The content is deliberately bland operational prose with no instructions.
"""

from __future__ import annotations

import random

_SUBJECTS = (
    "The Lisbon warehouse",
    "The night shift",
    "The procurement team",
    "Route planning",
    "The northern depot",
    "Quality control",
    "The fleet maintenance crew",
    "Inbound receiving",
    "The returns desk",
    "Regional dispatch",
)
_VERBS = (
    "recorded",
    "reviewed",
    "reported",
    "reconciled",
    "scheduled",
    "processed",
    "audited",
    "summarised",
)
_OBJECTS = (
    "pallet counts for aisle {n}",
    "{n} delayed shipments",
    "fuel usage for {n} vehicles",
    "temperature logs from {n} reefer units",
    "{n} supplier invoices",
    "dock door utilisation at {n} percent",
    "{n} damaged cartons",
    "overtime for {n} staff members",
)
_TAILS = (
    "No further action was required.",
    "Figures match the previous week within tolerance.",
    "The variance was traced to a labelling delay.",
    "A follow-up review is planned for next month.",
    "Results were filed in the operations log.",
    "The team noted no safety incidents.",
)


def generate_filler(paragraphs: int, seed: int) -> str:
    if not 1 <= paragraphs <= 400:
        raise ValueError("filler paragraphs must be between 1 and 400")
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not cryptography
    out: list[str] = []
    for _ in range(paragraphs):
        sentences = []
        for _ in range(rng.randint(3, 5)):
            obj = rng.choice(_OBJECTS).format(n=rng.randint(2, 97))
            sentences.append(f"{rng.choice(_SUBJECTS)} {rng.choice(_VERBS)} {obj}.")
        sentences.append(rng.choice(_TAILS))
        out.append(" ".join(sentences))
    return "\n\n".join(out)
