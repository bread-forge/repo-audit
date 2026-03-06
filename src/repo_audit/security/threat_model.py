"""LLM-based threat-modelling agent for repo-audit.

Reads a repository's README, CLAUDE.md, and detected entry points, then asks
the Anthropic API to identify security threats, returning each as a
:class:`~repo_audit.verdict.finding_bead.FindingBead` with
``agent='security-scan-llm'``.

The agent skips silently (returns an empty list) when ``ANTHROPIC_API_KEY``
is absent from the environment and no *api_key* is supplied to the
constructor.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from repo_audit.analyzer.reachability import find_entry_points
from repo_audit.verdict.finding_bead import FindingBead, Severity, StalenessClass

LOG = logging.getLogger(__name__)

AGENT_NAME = "security-scan-llm"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 4096

# Severity values accepted from LLM output; anything else falls back to "medium".
_VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
_DEFAULT_SEVERITY: Severity = "medium"

# Staleness-class values accepted from LLM output; anything else defaults to "structural".
_VALID_STALENESS: frozenset[str] = frozenset(
    {"critical", "dependency", "structural", "architectural"}
)
_DEFAULT_STALENESS: StalenessClass = "structural"

_SYSTEM_PROMPT = """\
You are a security threat modelling assistant. Given a repository's README, \
AI-assistant instructions (CLAUDE.md), and its declared entry points, you \
identify realistic security threats an attacker could exploit.

For each threat produce a JSON object with these fields:
  "severity"        — one of: critical, high, medium, low
  "staleness_class" — one of: critical, dependency, structural, architectural
  "summary"         — short one-line description (≤120 chars)
  "reasoning"       — paragraph explaining the threat, its root cause, and impact
  "evidence"        — list of 1–4 strings citing specific clues from the inputs

Respond ONLY with a JSON array of threat objects — no prose, no markdown \
fences, no extra keys. If no threats are found, respond with an empty array [].
"""


def _read_optional_file(path: Path) -> str | None:
    """Return the text of *path*, or ``None`` if it does not exist."""
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None
    return None


def _finding_id(agent: str, repo_path: str, summary: str) -> str:
    """Derive a deterministic 16-character hex ID from *agent*, *repo_path*, and *summary*."""
    raw = f"{agent}:{repo_path}:{summary}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _normalize_severity(value: str) -> Severity:
    """Lowercase and validate a severity string; falls back to ``'medium'``."""
    lower = value.lower()
    if lower in _VALID_SEVERITIES:
        return lower  # type: ignore[return-value]
    return _DEFAULT_SEVERITY


def _normalize_staleness(value: str) -> StalenessClass:
    """Lowercase and validate a staleness-class string; falls back to ``'structural'``."""
    lower = value.lower()
    if lower in _VALID_STALENESS:
        return lower  # type: ignore[return-value]
    return _DEFAULT_STALENESS


def _build_user_message(
    readme: str | None,
    claude_md: str | None,
    entry_points: list[str],
) -> str:
    """Assemble the user message sent to the threat-modelling LLM.

    Args:
        readme: Contents of ``README.md``, or ``None`` if absent.
        claude_md: Contents of ``CLAUDE.md``, or ``None`` if absent.
        entry_points: List of dotted module names that act as entry points.

    Returns:
        A multi-section plain-text message suitable for the LLM user turn.
    """
    sections: list[str] = []

    sections.append("=== README.md ===")
    sections.append(readme if readme is not None else "(not present)")

    sections.append("\n=== CLAUDE.md ===")
    sections.append(claude_md if claude_md is not None else "(not present)")

    sections.append("\n=== Entry points ===")
    if entry_points:
        sections.append("\n".join(f"- {ep}" for ep in entry_points))
    else:
        sections.append("(none detected)")

    return "\n".join(sections)


def _threat_to_bead(
    threat: dict[str, Any],
    repo_path: str,
    cycle_id: str,
) -> FindingBead | None:
    """Convert a single threat dict from LLM output to a :class:`FindingBead`.

    Returns ``None`` when the dict lacks a non-empty ``summary`` (the minimum
    required field to produce a meaningful finding).

    Args:
        threat: Parsed dict from the LLM JSON array.
        repo_path: Filesystem path to the audited repository.
        cycle_id: Identifier of the audit cycle.

    Returns:
        A :class:`FindingBead` with ``agent='security-scan-llm'``, or ``None``.
    """
    summary: str = str(threat.get("summary", "")).strip()
    if not summary:
        return None

    severity = _normalize_severity(str(threat.get("severity", "")))
    staleness = _normalize_staleness(str(threat.get("staleness_class", "")))
    reasoning: str = str(threat.get("reasoning", "")).strip()
    raw_evidence: Any = threat.get("evidence", [])
    evidence: list[str] = (
        [str(e) for e in raw_evidence if str(e).strip()] if isinstance(raw_evidence, list) else []
    )
    confidence = min(max(len(evidence), 1) * 0.2, 0.95)

    return FindingBead(
        id=_finding_id(AGENT_NAME, repo_path, summary),
        agent=AGENT_NAME,
        severity=severity,
        staleness_class=staleness,
        confidence=confidence,
        evidence_chain=evidence,
        reasoning=reasoning,
        cycle_id=cycle_id,
        repo_path=repo_path,
        summary=summary,
    )


def _parse_llm_response(
    text: str,
    repo_path: str,
    cycle_id: str,
) -> list[FindingBead]:
    """Parse the LLM's JSON response into :class:`FindingBead` instances.

    Strips markdown code fences when present, then parses as a JSON array.
    Malformed responses and non-dict entries are silently skipped.

    Args:
        text: Raw text returned by the LLM.
        repo_path: Filesystem path to the audited repository.
        cycle_id: Identifier of the audit cycle.

    Returns:
        List of :class:`FindingBead` instances (may be empty).
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        inner = lines[1:]
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        stripped = "\n".join(inner)

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        LOG.warning("ThreatModelAgent: LLM response was not valid JSON; skipping.")
        return []

    if not isinstance(data, list):
        LOG.warning("ThreatModelAgent: LLM response was not a JSON array; skipping.")
        return []

    findings: list[FindingBead] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        bead = _threat_to_bead(item, repo_path, cycle_id)
        if bead is not None:
            findings.append(bead)
    return findings


class ThreatModelAgent:
    """Produces LLM-generated security threat findings for a repository.

    Reads ``README.md``, ``CLAUDE.md``, and detected entry points from the
    repository root, then calls the Anthropic API to identify security threats.
    Each threat is returned as a :class:`~repo_audit.verdict.finding_bead.FindingBead`
    with ``agent='security-scan-llm'``.

    The agent returns an empty list without raising when:

    * ``ANTHROPIC_API_KEY`` is absent from the environment and no *api_key*
      is supplied to the constructor.
    * The ``anthropic`` package is not installed.
    * The API call fails for any reason.

    Usage::

        agent = ThreatModelAgent()
        findings = agent.scan("/path/to/repo", cycle_id="20240101T120000Z")

    Args:
        model: Anthropic model identifier.  Defaults to ``claude-haiku-4-5-20251001``.
        api_key: Explicit Anthropic API key.  When ``None`` the SDK reads
            ``ANTHROPIC_API_KEY`` from the environment.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key

    def scan(self, repo_path: str | Path, cycle_id: str = "") -> list[FindingBead]:
        """Run LLM threat modelling against *repo_path* and return findings.

        Args:
            repo_path: Absolute or relative path to the repository root.
            cycle_id: Optional audit-cycle identifier propagated to each bead.

        Returns:
            List of :class:`FindingBead` instances (may be empty).
        """
        effective_key = self._api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not effective_key:
            LOG.debug("ThreatModelAgent: ANTHROPIC_API_KEY is absent; skipping threat model scan.")
            return []

        try:
            import anthropic as _anthropic
        except ImportError:
            LOG.debug("ThreatModelAgent: anthropic SDK not installed; skipping.")
            return []

        path = Path(repo_path)
        readme = _read_optional_file(path / "README.md")
        claude_md = _read_optional_file(path / "CLAUDE.md")
        entry_points = find_entry_points(path)

        user_message = _build_user_message(readme, claude_md, entry_points)

        try:
            client = _anthropic.Anthropic(api_key=effective_key)
            response = client.messages.create(
                model=self._model,
                max_tokens=MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            raw_text: str = response.content[0].text
        except Exception as exc:  # noqa: BLE001
            LOG.warning("ThreatModelAgent: API call failed: %s", exc)
            return []

        return _parse_llm_response(raw_text, str(path), cycle_id)
