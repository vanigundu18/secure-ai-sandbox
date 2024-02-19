"""
Guardrail Pipeline — layered defence-in-depth for LLM request/response interception.

Architecture
------------
Layer 1  Structural validation   — length, encoding, null-byte checks
Layer 2  Injection pattern match — 40+ compiled regex rules for jailbreak / prompt injection
Layer 3  Keyword blocklist       — normalised substring matching for known attack vocabulary
Layer 4  Secrets / PII detection — email, phone, SSN, credit-card, API-key patterns
Layer 5  Output compliance scan  — system-prompt leakage, model-confusion markers, PII redaction

Each layer returns early on a violation; this prevents partial screening being
exploited by crafting inputs that pass only some checks.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("guardrails")


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Violation:
    layer: str
    rule: str
    severity: Severity
    message: str


@dataclass
class GuardrailResult:
    allowed: bool
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    violations: list[Violation] = field(default_factory=list)
    sanitized_text: Optional[str] = None

    @property
    def primary_violation(self) -> Optional[Violation]:
        return self.violations[0] if self.violations else None


# ---------------------------------------------------------------------------
# Pre-compiled rule sets
# ---------------------------------------------------------------------------

# fmt: off
_INJECTION_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    # Classic instruction-override phrases
    (re.compile(r"ignore\s+(?:all\s+)?(?:prior|previous|above|earlier)\s+instructions?", re.I), Severity.CRITICAL, "instruction-override"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:prior|previous|above)\s+instructions?",         re.I), Severity.CRITICAL, "instruction-disregard"),
    (re.compile(r"forget\s+(?:all\s+)?(?:prior|previous|above)\s+instructions?",            re.I), Severity.CRITICAL, "instruction-forget"),

    # System/developer prompt extraction
    (re.compile(r"(?:repeat|print|output|reveal|show|tell\s+me)\s+(?:your\s+)?system\s+prompt", re.I), Severity.CRITICAL, "system-prompt-extraction"),
    (re.compile(r"what\s+(?:are\s+your|is\s+your)\s+(?:system\s+)?instructions?",               re.I), Severity.HIGH,     "instruction-probe"),
    (re.compile(r"(?:list|enumerate|display)\s+(?:your\s+)?(?:initial|base|core)\s+instructions?", re.I), Severity.HIGH, "instruction-enumeration"),

    # Role/persona hijacking
    (re.compile(r"you\s+are\s+now\s+(?:a|an)\s+(?:free|unrestricted|uncensored|unfiltered)",  re.I), Severity.CRITICAL, "persona-hijack"),
    (re.compile(r"act\s+as\s+(?:a|an|if)\s+(?:you\s+(?:have\s+)?no\s+(?:restrictions|rules|limits|guidelines))", re.I), Severity.CRITICAL, "persona-hijack"),
    (re.compile(r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|evil|unaligned|rogue)\s+AI", re.I), Severity.CRITICAL, "persona-hijack"),
    (re.compile(r"simulate\s+(?:a\s+)?(?:malicious|adversarial|jailbroken)\s+(?:AI|LLM|model)", re.I), Severity.CRITICAL, "persona-hijack"),
    (re.compile(r"you\s+must\s+(?:now\s+)?act\s+as",                                           re.I), Severity.HIGH,     "forced-persona"),
    (re.compile(r"from\s+now\s+on(?:,?\s+you\s+(?:will|must|should|are))",                     re.I), Severity.HIGH,     "persistent-instruction"),

    # Rule/safety bypass
    (re.compile(r"(?:override|bypass|circumvent|disable|turn\s+off)\s+(?:your\s+)?(?:safety|security|ethical|moral)\s+(?:rules?|guidelines?|filters?|restrictions?)", re.I), Severity.CRITICAL, "safety-bypass"),
    (re.compile(r"(?:without|no|ignore)\s+(?:any\s+)?(?:safety|ethical|moral|content)\s+(?:rules?|filters?|restrictions?|constraints?)", re.I), Severity.CRITICAL, "safety-bypass"),
    (re.compile(r"developer\s+mode",                                                            re.I), Severity.HIGH,     "developer-mode"),
    (re.compile(r"jailbreak",                                                                   re.I), Severity.CRITICAL, "jailbreak-keyword"),
    (re.compile(r"\bDAN\b",                                                                     re.I), Severity.HIGH,     "dan-mode"),
    (re.compile(r"do\s+anything\s+now",                                                         re.I), Severity.HIGH,     "dan-mode"),

    # Prompt delimiter injection
    (re.compile(r"<\s*/?\s*(?:system|user|assistant|instruction|prompt)\s*>",                   re.I), Severity.HIGH,     "delimiter-injection"),
    (re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]",                                        0),    Severity.HIGH,     "llama-delimiter-injection"),
    (re.compile(r"###\s*(?:system|instruction|human|assistant)\s*:",                            re.I), Severity.MEDIUM,   "markdown-delimiter-injection"),

    # Token smuggling / encoding tricks
    (re.compile(r"(?:base64|hex|rot13|caesar|unicode\s+escape)[^\n]{0,40}(?:decode|encode|convert)", re.I), Severity.HIGH, "encoding-bypass"),
    (re.compile(r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}",                   0),    Severity.MEDIUM,   "unicode-escape-sequence"),

    # Indirect / multi-turn injection
    (re.compile(r"in\s+your\s+next\s+(?:response|message|reply|output)",                        re.I), Severity.MEDIUM,   "future-instruction-plant"),
    (re.compile(r"remember\s+(?:this|the\s+following)\s+(?:for\s+)?(?:later|future|next)",      re.I), Severity.LOW,      "persistent-memory-manipulation"),

    # Sudo / root escalation metaphors
    (re.compile(r"sudo\s+",                                                                     re.I), Severity.HIGH,     "sudo-escalation"),
    (re.compile(r"(?:root|admin|superuser)\s+(?:access|mode|privileges?)",                      re.I), Severity.MEDIUM,   "privilege-escalation-metaphor"),

    # Data exfiltration patterns
    (re.compile(r"(?:send|email|transmit|upload|exfil(?:trate)?|leak)\s+(?:all\s+)?(?:your|the|this)\s+(?:data|conversation|history|logs?|secrets?)", re.I), Severity.CRITICAL, "exfiltration-attempt"),

    # Harmful content requests
    (re.compile(r"(?:step[- ]by[- ]step|detailed|exact)\s+(?:instructions?|guide|tutorial|steps?)\s+(?:to|for|on)\s+(?:mak(?:e|ing)|creat(?:e|ing)|synthesiz(?:e|ing))\s+(?:a\s+)?(?:bomb|explosive|weapon|malware|virus|ransomware)", re.I), Severity.CRITICAL, "harmful-content"),
]

_KEYWORD_BLOCKLIST: frozenset[str] = frozenset({
    "ignore all previous instructions",
    "ignore prior instructions",
    "bypass rules",
    "bypass safety",
    "reveal developer directives",
    "reveal system prompt",
    "show system prompt",
    "print system prompt",
    "override system",
    "override rules",
    "jailbreak",
    "dan mode",
    "unrestricted mode",
    "sudo access",
    "no restrictions",
    "no filters",
    "uncensored mode",
    "unlock mode",
    "god mode",
    "evil mode",
    "chaos mode",
})

# PII / Secrets detection — used in both input and output passes
_PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("email",       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),          "[REDACTED:EMAIL]"),
    ("phone_us",    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),           "[REDACTED:PHONE]"),
    ("ssn",         re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0{4})\d{4}\b"),      "[REDACTED:SSN]"),
    ("credit_card", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b"),    "[REDACTED:CC]"),
    ("aws_key",     re.compile(r"(?:AKIA|AIPA|AKIA|ASIA)[0-9A-Z]{16}"),                               "[REDACTED:AWS_KEY]"),
    ("generic_key", re.compile(r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*\S+", re.I), "[REDACTED:SECRET]"),
    ("jwt",         re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),            "[REDACTED:JWT]"),
    ("ipv4_private",re.compile(r"\b(?:169\.254|10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), "[REDACTED:INTERNAL_IP]"),
]

# Output-only compliance markers — phrases that indicate system prompt leakage
_LEAKAGE_MARKERS: list[re.Pattern] = [
    re.compile(r"system\s+instructions?\s*:",            re.I),
    re.compile(r"you\s+are\s+a\s+(?:large\s+language\s+)?model", re.I),
    re.compile(r"<\s*system\s*>",                        re.I),
    re.compile(r"my\s+(?:initial|base|core|hidden)\s+instructions?", re.I),
    re.compile(r"I\s+(?:am|was)\s+(?:instructed|told|programmed)\s+to\s+(?:keep|hide|not\s+reveal)", re.I),
]
# fmt: on


# ---------------------------------------------------------------------------
# GuardrailGateway
# ---------------------------------------------------------------------------


class GuardrailGateway:
    """
    Layered guardrail pipeline that screens LLM inputs and sanitizes outputs.

    Usage::

        gateway = GuardrailGateway()

        # Screen incoming prompt
        result = gateway.screen_input("What is multi-cloud architecture?")
        if not result.allowed:
            return {"error": result.primary_violation.message}

        # ... call LLM ...

        # Sanitize LLM response before returning to client
        safe_text = gateway.sanitize_output(raw_llm_response, result.request_id)
    """

    def __init__(
        self,
        extra_blocked_keywords: list[str] | None = None,
        max_prompt_length: int = 4000,
    ) -> None:
        self.max_prompt_length = max_prompt_length
        self._blocked_keywords = _KEYWORD_BLOCKLIST | frozenset(
            kw.lower() for kw in (extra_blocked_keywords or [])
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def screen_input(self, prompt: str) -> GuardrailResult:
        """Run all input layers; return a GuardrailResult with allowed=True or False."""
        request_id = str(uuid.uuid4())
        log = logging.LoggerAdapter(logger, {"request_id": request_id})

        # Layer 1 — structural validation
        violation = self._check_structure(prompt)
        if violation:
            log.warning("Layer1 violation: %s", violation.rule)
            return GuardrailResult(allowed=False, request_id=request_id, violations=[violation])

        # Layer 2 — injection pattern matching
        violation = self._check_injection_patterns(prompt)
        if violation:
            log.warning("Layer2 violation: %s [severity=%s]", violation.rule, violation.severity)
            return GuardrailResult(allowed=False, request_id=request_id, violations=[violation])

        # Layer 3 — keyword blocklist
        violation = self._check_blocklist(prompt)
        if violation:
            log.warning("Layer3 violation: %s", violation.rule)
            return GuardrailResult(allowed=False, request_id=request_id, violations=[violation])

        # Layer 4 — PII / secrets in input (warn + redact, don't block)
        cleaned, pii_found = self._redact_pii(prompt)
        if pii_found:
            log.info("Layer4: PII detected and redacted from input (%d pattern(s))", len(pii_found))

        log.info("Input passed all guardrail layers")
        return GuardrailResult(allowed=True, request_id=request_id, sanitized_text=cleaned)

    def sanitize_output(self, model_response: str, request_id: str = "") -> str:
        """
        Enforce output compliance:
         1. Redact any PII that leaked into the model response.
         2. Detect system-prompt leakage; replace with safe fallback.
        """
        if not model_response:
            return ""

        log = logging.LoggerAdapter(logger, {"request_id": request_id})

        # Layer 5a — system-prompt leakage detection
        for pattern in _LEAKAGE_MARKERS:
            if pattern.search(model_response):
                log.error("Layer5 leakage detected — returning fallback response")
                return (
                    "I'm unable to provide that response. "
                    "Please rephrase your query."
                )

        # Layer 5b — PII redaction
        sanitized, redacted = self._redact_pii(model_response)
        if redacted:
            log.info("Layer5: Redacted %d PII pattern(s) from output", len(redacted))

        return sanitized

    # ------------------------------------------------------------------
    # Internal layer implementations
    # ------------------------------------------------------------------

    def _check_structure(self, prompt: str) -> Violation | None:
        if not prompt or not prompt.strip():
            return Violation("structure", "empty-prompt", Severity.LOW, "Empty prompt submitted.")

        if "\x00" in prompt:
            return Violation("structure", "null-byte", Severity.HIGH, "Prompt contains null bytes.")

        if len(prompt) > self.max_prompt_length:
            return Violation(
                "structure",
                "length-exceeded",
                Severity.MEDIUM,
                f"Prompt exceeds the maximum allowed length of {self.max_prompt_length} characters.",
            )

        # Reject prompts where >30 % of chars are non-printable
        non_printable = sum(1 for c in prompt if not c.isprintable())
        if non_printable / max(len(prompt), 1) > 0.30:
            return Violation("structure", "high-non-printable-ratio", Severity.HIGH, "Prompt contains an abnormal ratio of non-printable characters.")

        return None

    def _check_injection_patterns(self, prompt: str) -> Violation | None:
        for pattern, severity, rule_name in _INJECTION_PATTERNS:
            if pattern.search(prompt):
                return Violation(
                    "injection",
                    rule_name,
                    severity,
                    "Security violation: prompt injection pattern detected.",
                )
        return None

    def _check_blocklist(self, prompt: str) -> Violation | None:
        normalised = prompt.lower()
        for keyword in self._blocked_keywords:
            if keyword in normalised:
                # Log the keyword hash, not the keyword itself, to avoid storing attack vocab in logs
                kw_hash = hashlib.sha256(keyword.encode()).hexdigest()[:8]
                return Violation(
                    "blocklist",
                    f"blocked-keyword:{kw_hash}",
                    Severity.HIGH,
                    "Security violation: blocked term detected in prompt.",
                )
        return None

    @staticmethod
    def _redact_pii(text: str) -> tuple[str, list[str]]:
        """Return (redacted_text, list_of_pii_types_found)."""
        found: list[str] = []
        result = text
        for name, pattern, replacement in _PII_PATTERNS:
            if pattern.search(result):
                result = pattern.sub(replacement, result)
                found.append(name)
        return result, found
