"""Approximate token counter.

This is a lightweight heuristic intended for demos, quota accounting and
telemetry. It does **not** reproduce the tokenizer of any commercial LLM;
real deployments should plug in the provider's tokenizer (e.g. ``tiktoken``).

Heuristic: every word counts as one token plus one extra token per six
characters beyond the first, and every punctuation symbol counts as a token.
On typical English prose this lands within roughly ±20% of BPE tokenizers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TOKEN_PATTERN = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def count_tokens(text: str | None) -> int:
    """Return the approximate number of tokens in ``text``."""
    if not text:
        return 0
    total = 0
    for piece in _TOKEN_PATTERN.findall(text):
        if piece[0].isalnum() or piece[0] == "_":
            total += 1 + (len(piece) - 1) // 6
        else:
            total += 1
    return total


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Input/output/total token accounting for a single transaction."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }
