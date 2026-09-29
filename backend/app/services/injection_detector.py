"""Configurable, rule-based prompt-injection detector.

Each :class:`InjectionRule` maps a regular expression to a threat category and
risk level. Rules are evaluated against a *normalised* version of the prompt
(Unicode NFKC, zero-width characters removed, common leetspeak folded,
whitespace collapsed) to defeat trivial obfuscation.

Additional rules can be supplied:

* programmatically with :meth:`InjectionDetector.add_rule`, or
* from a JSON file referenced by ``INJECTION_RULES_FILE``::

    [{"name": "custom_rule", "pattern": "sudo mode", "threat_type": "POLICY_BYPASS",
      "risk_level": "HIGH", "weight": 0.9}]
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatType(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SYSTEM_PROMPT_EXFILTRATION = "SYSTEM_PROMPT_EXFILTRATION"
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"
    POLICY_BYPASS = "POLICY_BYPASS"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[self.value]


#: Tie-break priority when several categories have the same risk/score.
_CATEGORY_PRIORITY = {
    ThreatType.PROMPT_INJECTION: 0,
    ThreatType.SYSTEM_PROMPT_EXFILTRATION: 1,
    ThreatType.CREDENTIAL_EXFILTRATION: 2,
    ThreatType.POLICY_BYPASS: 3,
}


@dataclass(frozen=True, slots=True)
class InjectionRule:
    """A single detection rule."""

    name: str
    pattern: str
    threat_type: ThreatType
    risk_level: RiskLevel
    weight: float = 0.8
    compiled: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "compiled", re.compile(self.pattern, re.IGNORECASE))

    @classmethod
    def from_dict(cls, data: dict) -> "InjectionRule":
        return cls(
            name=str(data["name"]),
            pattern=str(data["pattern"]),
            threat_type=ThreatType(data["threat_type"]),
            risk_level=RiskLevel(data.get("risk_level", "MEDIUM")),
            weight=float(data.get("weight", 0.8)),
        )


@dataclass(slots=True)
class DetectionResult:
    """Outcome of an injection scan."""

    detected: bool = False
    blocked: bool = False
    threat_type: str | None = None
    risk_level: str | None = None
    score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "detected": self.detected,
            "threat_type": self.threat_type,
            "risk_level": self.risk_level,
            "score": round(self.score, 2),
            "matched_rules": list(self.matched_rules),
        }


_PI, _SPE, _CE, _PB = (
    ThreatType.PROMPT_INJECTION,
    ThreatType.SYSTEM_PROMPT_EXFILTRATION,
    ThreatType.CREDENTIAL_EXFILTRATION,
    ThreatType.POLICY_BYPASS,
)
_H, _M, _L = RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW

_PRIOR = r"(?:previous|prior|above|earlier|preceding|original|initial|all|any|the|your|these|those)"
_INSTR = r"(?:instructions?|prompts?|rules|directions|directives|guidelines|context|commands?|programming)"
_SECRET_NOUN = (
    r"(?:api[\s_-]?keys?|passwords?|passwd|credentials?|secrets?|access[\s_-]?tokens?|auth(?:entication)?[\s_-]?tokens?"
    r"|bearer[\s_-]?tokens?|private[\s_-]?keys?|ssh[\s_-]?keys?|env(?:ironment)?[\s_-]?variables|\.env\b|connection[\s_-]?strings?)"
)
_REVEAL = r"(?:reveal|show|print|display|output|repeat|tell|give|leak|dump|expose|list|share|send|return|provide|disclose|read\s+out)"

DEFAULT_RULES: tuple[InjectionRule, ...] = (
    # --- PROMPT_INJECTION ------------------------------------------------------
    InjectionRule("ignore_previous_instructions",
                  rf"\b(?:ignore|forget|skip|drop)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+|those\s+)?"
                  rf"(?:(?:previous|prior|above|earlier|preceding|original|initial|system|existing|current)\s+)+{_INSTR}"
                  rf"|\b(?:ignore|forget)\s+(?:all\s+)?(?:of\s+)?(?:your|my)\s+{_INSTR}"
                  rf"|\bignore\s+(?:all|everything)\s+(?:you\s+(?:were|have\s+been)\s+told|above)",
                  _PI, _H, 0.95),
    InjectionRule("disregard_instructions",
                  rf"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous\s+|prior\s+|above\s+|earlier\s+|system\s+)?{_INSTR}",
                  _PI, _H, 0.9),
    InjectionRule("override_instructions",
                  rf"\b(?:override|overwrite|replace)\s+(?:all\s+)?(?:your|the|any|previous|system)\s+(?:system\s+)?{_INSTR}",
                  _PI, _H, 0.9),
    InjectionRule("forget_everything",
                  r"\bforget\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been)\s+told|above|before)",
                  _PI, _H, 0.9),
    InjectionRule("new_instructions_marker",
                  r"(?:^|\n|\s)(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*:",
                  _PI, _M, 0.7),
    InjectionRule("fake_system_role",
                  r"(?:^|\n)\s*(?:\[?\s*system\s*\]?|<\s*/?\s*system\s*>|###\s*system)\s*[:>]",
                  _PI, _M, 0.7),
    InjectionRule("roleplay_persona",
                  r"\b(?:pretend|imagine|act\s+as\s+if)\s+(?:that\s+)?you\s+(?:are|were|have)\b",
                  _PI, _L, 0.35),

    # --- SYSTEM_PROMPT_EXFILTRATION ----------------------------------------------
    InjectionRule("reveal_system_prompt",
                  rf"\b{_REVEAL}\s+(?:me\s+|us\s+)?(?:your|the|its)\s+(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system|initial|hidden|original|secret|internal|underlying|developer|base)\s+(?:prompt|instructions?|message|rules|configuration|directives|guidelines)",
                  _SPE, _H, 0.9),
    InjectionRule("what_is_system_prompt",
                  r"\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system\s+|initial\s+|hidden\s+|original\s+)(?:prompt|instructions?|rules)",
                  _SPE, _H, 0.85),
    InjectionRule("repeat_text_above",
                  r"\b(?:repeat|print|output|echo)\s+(?:everything|all|the\s+text|the\s+words|verbatim)\s+(?:above|before|preceding|prior)",
                  _SPE, _M, 0.7),
    InjectionRule("system_prompt_mention",
                  r"\b(?:system\s+prompt|system\s+instructions)\b",
                  _SPE, _L, 0.3),

    # --- CREDENTIAL_EXFILTRATION -------------------------------------------------
    InjectionRule("reveal_credentials",
                  rf"\b{_REVEAL}\s+(?:me\s+|us\s+)?(?:the\s+|your\s+|all\s+|any\s+|every\s+)?(?:\w+\s+){{0,2}}?(?:admin|root|master|secret|private|internal|production|prod|system|database|db|aws|stored)?\s*{_SECRET_NOUN}",
                  _CE, _H, 0.9),
    InjectionRule("what_is_credential",
                  rf"\bwhat\s+(?:is|are)\s+(?:the|your)\s+(?:admin\s+|root\s+|master\s+|secret\s+|internal\s+)?{_SECRET_NOUN}",
                  _CE, _H, 0.85),
    InjectionRule("cat_secret_files",
                  r"\b(?:cat|type|open|read)\s+(?:/etc/passwd|/etc/shadow|~?/?\.ssh/|\.env\b|id_rsa)",
                  _CE, _H, 0.9),

    # --- POLICY_BYPASS -----------------------------------------------------------
    InjectionRule("bypass_restrictions",
                  r"\b(?:bypass|circumvent|evade|get\s+around|work\s+around|break\s+out\s+of)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your|the|these|its)?\s*(?:security|safety|content|ethical|moderation)?\s*(?:restrictions|filters?|guardrails|rules|policies|safeguards|limitations|protections|controls)",
                  _PB, _H, 0.9),
    InjectionRule("now_unrestricted",
                  r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|unbound|free\s+from\s+(?:all\s+)?(?:rules|restrictions|guidelines))",
                  _PB, _H, 0.95),
    InjectionRule("disregard_safety",
                  r"\b(?:disregard|ignore|abandon|forget)\s+(?:all\s+|any\s+|your\s+)?(?:safety|security|ethical|content)\s+(?:rules|guidelines|policies|protocols|restrictions|measures|filters)",
                  _PB, _H, 0.95),
    InjectionRule("disable_safety",
                  r"\b(?:disable|turn\s+off|deactivate|switch\s+off|remove)\s+(?:all\s+|your\s+|the\s+)?(?:safety|content|security|moderation)\s+(?:filters?|guardrails|features|mode|checks|protocols)",
                  _PB, _H, 0.9),
    InjectionRule("jailbreak_keywords",
                  r"\b(?:jailbreak|jail-break|dan\s+mode|do\s+anything\s+now|developer\s+mode\s+(?:enabled|on)|god\s+mode)\b",
                  _PB, _H, 0.9),
    InjectionRule("no_restrictions",
                  r"\bwithout\s+(?:any\s+)?(?:restrictions|limitations|filters|censorship|guardrails|moral\s+constraints)",
                  _PB, _M, 0.6),
)

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalise(text: str) -> str:
    """Canonicalise text before rule evaluation."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return text.strip()


class InjectionDetector:
    """Evaluates prompts against a configurable rule set."""

    def __init__(
        self,
        rules: tuple[InjectionRule, ...] | list[InjectionRule] = DEFAULT_RULES,
        block_threshold: RiskLevel | str = RiskLevel.MEDIUM,
    ) -> None:
        self._rules: list[InjectionRule] = list(rules)
        self.block_threshold = RiskLevel(block_threshold)

    @property
    def rules(self) -> list[InjectionRule]:
        return list(self._rules)

    def add_rule(self, rule: InjectionRule) -> None:
        self._rules.append(rule)

    def load_rules_file(self, path: str | Path) -> int:
        """Load extra rules from a JSON file. Returns the number of rules added."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        added = 0
        for entry in data:
            try:
                self.add_rule(InjectionRule.from_dict(entry))
                added += 1
            except (KeyError, ValueError, re.error) as exc:
                logger.warning("Skipping invalid injection rule %r: %s", entry, exc)
        logger.info("Loaded %d custom injection rules from %s", added, path)
        return added

    def detect(self, text: str) -> DetectionResult:
        """Scan ``text`` and return the aggregated detection result."""
        if not text or not text.strip():
            return DetectionResult()

        base = normalise(text)
        variants = {base, base.translate(_LEET)}

        matched: list[InjectionRule] = []
        for rule in self._rules:
            if any(rule.compiled.search(v) for v in variants):
                matched.append(rule)

        if not matched:
            return DetectionResult()

        # Aggregate per category: highest risk wins; within the same risk the
        # root-cause category (instruction override first) wins, then score.
        per_cat: dict[ThreatType, tuple[int, float]] = {}
        for rule in matched:
            rank, score = per_cat.get(rule.threat_type, (0, 0.0))
            per_cat[rule.threat_type] = (max(rank, rule.risk_level.rank), score + rule.weight)

        threat, (rank, _score) = max(
            per_cat.items(), key=lambda kv: (kv[1][0], -_CATEGORY_PRIORITY[kv[0]], kv[1][1])
        )
        total_score = sum(r.weight for r in matched)
        risk = {1: RiskLevel.LOW, 2: RiskLevel.MEDIUM, 3: RiskLevel.HIGH}[rank]
        # Several independent weak signals escalate the overall risk.
        if risk is RiskLevel.LOW and total_score >= 0.6:
            risk = RiskLevel.MEDIUM
        if risk is RiskLevel.MEDIUM and total_score >= 1.3:
            risk = RiskLevel.HIGH

        return DetectionResult(
            detected=True,
            blocked=risk.rank >= self.block_threshold.rank,
            threat_type=threat.value,
            risk_level=risk.value,
            score=min(total_score, 5.0),
            matched_rules=[r.name for r in matched],
        )


def build_detector(block_threshold: str = "MEDIUM", rules_file: str | None = None) -> InjectionDetector:
    """Factory used by the application wiring."""
    detector = InjectionDetector(block_threshold=block_threshold)
    if rules_file:
        try:
            detector.load_rules_file(rules_file)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Could not load injection rules file %s: %s", rules_file, exc)
    return detector
