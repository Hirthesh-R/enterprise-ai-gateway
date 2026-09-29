"""Tests for the PII scrubbing engine."""

from __future__ import annotations

import re

import pytest

from app.services.pii_scrubber import PIIPattern, PIIScrubber, luhn_valid, pii_scrubber


@pytest.fixture()
def scrubber() -> PIIScrubber:
    return PIIScrubber()


# --------------------------------------------------------------------- email
@pytest.mark.parametrize(
    "text",
    [
        "Contact john@example.com please",
        "Mail JOHN.DOE+billing@sub.example.co.uk now",
        "reach me at john [at] example [dot] com",
        "email: jane_doe99@company-mail.io.",
    ],
)
def test_email_detection(scrubber: PIIScrubber, text: str) -> None:
    result = scrubber.scrub(text)
    assert "[REDACTED_EMAIL]" in result.redacted_text
    assert result.detected_types == ["EMAIL"]
    assert result.redaction_count == 1
    assert "@" not in result.redacted_text


def test_email_example_from_spec(scrubber: PIIScrubber) -> None:
    assert scrubber.scrub("john@example.com").redacted_text == "[REDACTED_EMAIL]"


# --------------------------------------------------------------------- phone
@pytest.mark.parametrize(
    "phone",
    [
        "+91 9876543210",
        "+1-555-123-4567",
        "+1 (555) 123-4567",
        "(555) 123-4567",
        "555.123.4567",
        "+44 20 7946 0958",
        "9876543210",
    ],
)
def test_phone_detection(scrubber: PIIScrubber, phone: str) -> None:
    result = scrubber.scrub(f"Call me on {phone} tomorrow")
    assert result.redacted_text == "Call me on [REDACTED_PHONE] tomorrow"
    assert result.detected_types == ["PHONE"]


# --------------------------------------------------------------- credit card
@pytest.mark.parametrize(
    "card",
    [
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "4111111111111111",
        "5500 0000 0000 0004",
        "3782 822463 10005",  # Amex layout (Luhn valid)
        "1234 5678 9012 3456",  # not Luhn-valid but classic grouped card layout
    ],
)
def test_credit_card_detection(scrubber: PIIScrubber, card: str) -> None:
    result = scrubber.scrub(f"My card is {card}.")
    assert result.redacted_text == "My card is [REDACTED_CREDIT_CARD]."
    assert result.detected_types == ["CREDIT_CARD"]


def test_luhn_checksum() -> None:
    assert luhn_valid("4111111111111111")
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("123")  # too short


def test_random_long_number_is_not_a_card(scrubber: PIIScrubber) -> None:
    # 16 ungrouped digits failing Luhn → not a card (may still be something else, but never a card)
    result = scrubber.scrub("Order reference 1234567812345678")
    assert "CREDIT_CARD" not in result.detected_types


# ----------------------------------------------------------------------- SSN
@pytest.mark.parametrize("ssn", ["123-45-6789", "123 45 6789"])
def test_ssn_detection(scrubber: PIIScrubber, ssn: str) -> None:
    result = scrubber.scrub(f"SSN on file: {ssn}")
    assert "[REDACTED_SSN]" in result.redacted_text
    assert result.detected_types == ["SSN"]


def test_ssn_without_separators_requires_context(scrubber: PIIScrubber) -> None:
    assert scrubber.scrub("SSN: 123456789").detected_types == ["SSN"]


@pytest.mark.parametrize("invalid", ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"])
def test_invalid_ssn_ranges_are_ignored(scrubber: PIIScrubber, invalid: str) -> None:
    assert "SSN" not in scrubber.scrub(f"value {invalid}").detected_types


# ------------------------------------------------------------ multiple types
def test_multiple_pii_types(scrubber: PIIScrubber) -> None:
    text = (
        "I'm john@example.com, phone +1-555-123-4567, card 4111 1111 1111 1111 "
        "and SSN 123-45-6789. Backup email jane@corp.org"
    )
    result = scrubber.scrub(text)
    assert result.redaction_count == 5
    assert result.detected_types == ["EMAIL", "CREDIT_CARD", "SSN", "PHONE"]
    assert result.counts == {"EMAIL": 2, "CREDIT_CARD": 1, "SSN": 1, "PHONE": 1}
    # No digits of the original values survive.
    assert not re.search(r"\d{3}", result.redacted_text)
    assert result.as_dict() == {
        "redacted_text": result.redacted_text,
        "redaction_count": 5,
        "detected_types": ["EMAIL", "CREDIT_CARD", "SSN", "PHONE"],
    }


# ----------------------------------------------------------- false positives
@pytest.mark.parametrize(
    "text",
    [
        "Summarize the Q3 2026 report released on 2026-09-29.",
        "Upgrade from version 3.11.6 to 3.12.1",
        "The meeting is at 10:30 in room 402",
        "We sold 1500 units for $12,000",
        "Explain the difference between TCP and UDP",
        "",
    ],
)
def test_no_false_positives(scrubber: PIIScrubber, text: str) -> None:
    result = scrubber.scrub(text)
    assert result.redaction_count == 0
    assert result.redacted_text == text
    assert not result.has_pii
    assert not scrubber.contains_pii(text)


# ------------------------------------------------------------- extensibility
def test_register_custom_pattern(scrubber: PIIScrubber) -> None:
    scrubber.register(PIIPattern("EMPLOYEE_ID", re.compile(r"\bEMP-\d{6}\b")))
    result = scrubber.scrub("Badge EMP-123456 for john@example.com")
    assert result.redacted_text == "Badge [REDACTED_EMPLOYEE_ID] for [REDACTED_EMAIL]"
    assert "EMPLOYEE_ID" in scrubber.supported_types


def test_register_before_existing_type(scrubber: PIIScrubber) -> None:
    scrubber.register(PIIPattern("IBAN", re.compile(r"\bGB\d{2}[A-Z]{4}\d{14}\b")), before="PHONE")
    assert scrubber.supported_types.index("IBAN") < scrubber.supported_types.index("PHONE")
    assert scrubber.scrub("IBAN GB29NWBK60161331926819").detected_types == ["IBAN"]


def test_validator_can_reject_matches() -> None:
    scrubber = PIIScrubber([PIIPattern("CODE", re.compile(r"\d{4}"), validator=lambda v: v != "0000")])
    result = scrubber.scrub("codes 0000 and 1234")
    assert result.redacted_text == "codes 0000 and [REDACTED_CODE]"


def test_singleton_available() -> None:
    assert pii_scrubber.contains_pii("john@example.com")
