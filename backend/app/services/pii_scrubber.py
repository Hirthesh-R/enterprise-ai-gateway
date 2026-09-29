"""Regex-based PII detection & redaction engine.

Detectors run in a fixed order (EMAIL → CREDIT_CARD → SSN → PHONE) on the
progressively redacted text. Placeholders contain no digits, so a number that
was already classified (e.g. a card number) can never be re-matched as a phone.

New detectors can be registered at runtime with :meth:`PIIScrubber.register`.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

Validator = Callable[[str], bool]


def luhn_valid(number: str) -> bool:
    """Return ``True`` when the digits of ``number`` pass the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _valid_credit_card(candidate: str) -> bool:
    """Accept Luhn-valid numbers, or classic 4-4-4-4 grouped card layouts.

    The grouped fallback deliberately errs on the side of redaction: for a
    compliance proxy a false positive is far cheaper than leaking a card.
    """
    digits = _digits(candidate)
    if not 13 <= len(digits) <= 19:
        return False
    if luhn_valid(digits):
        return True
    return bool(re.fullmatch(r"\d{4}([ -])\d{4}\1\d{4}\1\d{4}", candidate.strip()))


def _valid_ssn(candidate: str) -> bool:
    digits = _digits(candidate)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in {"000", "666"} and not area.startswith("9") and group != "00" and serial != "0000"


def _valid_phone(candidate: str) -> bool:
    digits = _digits(candidate)
    has_plus = candidate.strip().startswith("+")
    has_formatting = bool(re.search(r"[\s().-]", candidate.strip()))
    if has_plus:
        return 8 <= len(digits) <= 15
    if has_formatting:
        return 10 <= len(digits) <= 15
    return 10 <= len(digits) <= 13


@dataclass(frozen=True, slots=True)
class PIIPattern:
    """A single PII detector definition."""

    pii_type: str
    regex: re.Pattern[str]
    validator: Validator | None = None

    @property
    def placeholder(self) -> str:
        return f"[REDACTED_{self.pii_type}]"


@dataclass(slots=True)
class PIIResult:
    """Outcome of a scrub operation. Contains no raw PII values."""

    redacted_text: str
    redaction_count: int = 0
    detected_types: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return self.redaction_count > 0

    def as_dict(self) -> dict:
        return {
            "redacted_text": self.redacted_text,
            "redaction_count": self.redaction_count,
            "detected_types": list(self.detected_types),
        }


_EMAIL = re.compile(
    r"""(?<![\w.+-])
        [A-Za-z0-9._%+-]+
        (?:@|\s*[\[(]\s*at\s*[\])]\s*)
        [A-Za-z0-9-]+(?:(?:\.|\s*[\[(]\s*dot\s*[\])]\s*)[A-Za-z0-9-]+)*
        (?:\.|\s*[\[(]\s*dot\s*[\])]\s*)[A-Za-z]{2,24}
        (?![\w-])""",
    re.VERBOSE | re.IGNORECASE,
)

_CREDIT_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

_SSN = re.compile(
    r"""(?<![\d-])
        (?:
            \d{3}([- ])\d{2}\1\d{4}                           # 123-45-6789 / 123 45 6789
          | (?<=SSN[:\s#])\s*\d{9}                             # SSN: 123456789
          | (?<=social\ security\ number[:\s])\s*\d{9}
        )
        (?![\d-])""",
    re.VERBOSE | re.IGNORECASE,
)

_PHONE = re.compile(
    r"""(?<![\w+])
        (?:\+\d{1,3}[\s.-]?)?                 # country code
        (?:\(\d{1,4}\)[\s.-]?)?               # (area code)
        \d{2,5}(?:[\s.-]?\d{2,5}){1,4}        # subscriber groups
        (?![\w])""",
    re.VERBOSE,
)

DEFAULT_PATTERNS: tuple[PIIPattern, ...] = (
    PIIPattern("EMAIL", _EMAIL),
    PIIPattern("CREDIT_CARD", _CREDIT_CARD, _valid_credit_card),
    PIIPattern("SSN", _SSN, _valid_ssn),
    PIIPattern("PHONE", _PHONE, _valid_phone),
)


class PIIScrubber:
    """Reusable PII detection/redaction service."""

    def __init__(self, patterns: tuple[PIIPattern, ...] | list[PIIPattern] = DEFAULT_PATTERNS) -> None:
        self._patterns: list[PIIPattern] = list(patterns)

    @property
    def supported_types(self) -> list[str]:
        return [p.pii_type for p in self._patterns]

    def register(self, pattern: PIIPattern, *, before: str | None = None) -> None:
        """Add a detector, optionally ahead of an existing type."""
        if before:
            idx = next((i for i, p in enumerate(self._patterns) if p.pii_type == before), len(self._patterns))
            self._patterns.insert(idx, pattern)
        else:
            self._patterns.append(pattern)

    def scrub(self, text: str) -> PIIResult:
        """Detect and redact all supported PII in ``text``."""
        if not text:
            return PIIResult(redacted_text=text or "")

        counts: Counter[str] = Counter()
        redacted = text

        for pattern in self._patterns:
            def _replace(match: re.Match[str], _p: PIIPattern = pattern) -> str:
                value = match.group(0)
                if _p.validator is not None and not _p.validator(value):
                    return value
                counts[_p.pii_type] += 1
                # Keep surrounding whitespace that the pattern may have consumed.
                lead = value[: len(value) - len(value.lstrip())]
                return f"{lead}{_p.placeholder}"

            redacted = pattern.regex.sub(_replace, redacted)

        detected = [p.pii_type for p in self._patterns if counts.get(p.pii_type)]
        return PIIResult(
            redacted_text=redacted,
            redaction_count=sum(counts.values()),
            detected_types=detected,
            counts={t: counts[t] for t in detected},
        )

    def contains_pii(self, text: str) -> bool:
        return self.scrub(text).has_pii


pii_scrubber = PIIScrubber()
