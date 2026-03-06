"""Scoring heuristics that map GapSignal attributes to FindingBead fields.

Each GapSignal carries a ``layer`` (which comparison produced it) and a
``kind`` (what category of gap was detected).  The scorer uses both to derive:

- **severity** — how impactful the gap is at runtime.
- **staleness_class** — what category of technical debt it represents.
- **confidence** — how reliable the finding is, based on evidence count.
- **reasoning** — a human-readable explanation of why the gap was flagged.
- **evidence_chain** — the evidence list from the originating signal.
- **summary** — a short one-line description.

Priority rule: ``kind``-level overrides supersede ``layer``-level defaults for
both severity and staleness_class, so that e.g. a ``broken_entry_point`` in an
unexpected layer still scores as ``critical``.
"""

from __future__ import annotations

import hashlib

from repo_audit.comparator.gap_signal import GapSignal
from repo_audit.verdict.finding_bead import FindingBead, Severity, StalenessClass

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

# Default severity derived from the layer that produced the signal.
_LAYER_SEVERITY: dict[str, Severity] = {
    "declared_vs_structural": "low",
    "structural_vs_behavioral": "medium",
    "behavioral_vs_activated": "critical",
    "test_vs_declared": "high",
}

# Kind-level severity overrides (applied on top of layer defaults).
_KIND_SEVERITY: dict[str, Severity] = {
    "undocumented_module": "low",
    "unreachable_module": "medium",
    "broken_entry_point": "critical",
    "untested_goal": "high",
}

# Default staleness class derived from the layer.
_LAYER_STALENESS: dict[str, StalenessClass] = {
    "declared_vs_structural": "architectural",
    "structural_vs_behavioral": "structural",
    "behavioral_vs_activated": "critical",
    "test_vs_declared": "dependency",
}

# Kind-level staleness overrides.
_KIND_STALENESS: dict[str, StalenessClass] = {
    "undocumented_module": "architectural",
    "unreachable_module": "structural",
    "broken_entry_point": "critical",
    "untested_goal": "dependency",
}

# Severity ordering used to resolve ties by taking the higher of two values.
_SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_BY_RANK: list[Severity] = ["low", "medium", "high", "critical"]

# Human-readable descriptions used in the reasoning paragraph.
_LAYER_DESC: dict[str, str] = {
    "declared_vs_structural": "documentation layer vs structural layer",
    "structural_vs_behavioral": "structural layer vs behavioral layer",
    "behavioral_vs_activated": "behavioral layer vs activated (entry-point) layer",
    "test_vs_declared": "declared goals vs test coverage",
}

_KIND_DESC: dict[str, str] = {
    "undocumented_module": "lacks a module-level docstring",
    "unreachable_module": "is unreachable from any declared entry point",
    "broken_entry_point": "references a module not found in the import graph",
    "untested_goal": "has no associated test-module coverage",
}

# Confidence cap — never claim more than 95% certainty regardless of evidence.
_MAX_CONFIDENCE = 0.95
_CONFIDENCE_PER_EVIDENCE = 0.2


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _severity_for(signal: GapSignal) -> Severity:
    """Return the higher of the layer-level and kind-level severity."""
    layer_sev: Severity = _LAYER_SEVERITY.get(signal.layer, "medium")
    kind_sev: Severity = _KIND_SEVERITY.get(signal.kind, layer_sev)
    layer_rank = _SEVERITY_RANK.get(layer_sev, 1)
    kind_rank = _SEVERITY_RANK.get(kind_sev, 1)
    return _SEVERITY_BY_RANK[max(layer_rank, kind_rank)]


def _staleness_for(signal: GapSignal) -> StalenessClass:
    """Return the staleness class, preferring kind-level over layer-level."""
    if signal.kind in _KIND_STALENESS:
        return _KIND_STALENESS[signal.kind]
    return _LAYER_STALENESS.get(signal.layer, "structural")


def _confidence_for(signal: GapSignal) -> float:
    """Compute confidence as min(len(evidence) * 0.2, 0.95)."""
    return min(len(signal.evidence) * _CONFIDENCE_PER_EVIDENCE, _MAX_CONFIDENCE)


def _reasoning_for(signal: GapSignal) -> str:
    """Compose a reasoning paragraph from layer, kind, subject, and evidence."""
    layer_desc = _LAYER_DESC.get(signal.layer, signal.layer)
    kind_desc = _KIND_DESC.get(signal.kind, signal.kind.replace("_", " "))
    sentences: list[str] = [f"Gap detected in {layer_desc}: {signal.subject!r} {kind_desc}."]
    if signal.evidence:
        evidence_text = "; ".join(signal.evidence)
        sentences.append(f"Supporting evidence: {evidence_text}.")
    return " ".join(sentences)


def _summary_for(signal: GapSignal) -> str:
    """Produce a short one-line summary from kind and subject."""
    kind_label = signal.kind.replace("_", " ").title()
    return f"{kind_label}: {signal.subject}"


def _signal_id(signal: GapSignal) -> str:
    """Derive a deterministic 16-character hex ID from layer, kind, and subject."""
    key = f"{signal.layer}:{signal.kind}:{signal.subject}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

AGENT_NAME = "repo-audit"


def score_signal(
    signal: GapSignal,
    cycle_id: str = "",
    repo_path: str = "",
    agent: str = AGENT_NAME,
) -> FindingBead:
    """Convert a single :class:`~repo_audit.comparator.gap_signal.GapSignal` into a
    scored :class:`~repo_audit.verdict.finding_bead.FindingBead`.

    Args:
        signal: The gap signal to score.
        cycle_id: Identifier of the audit cycle; passed through to the bead.
        repo_path: Filesystem path of the audited repository; passed through.
        agent: Name of the scoring agent.  Defaults to ``"repo-audit"``.

    Returns:
        A :class:`FindingBead` with all fields populated from the signal and
        the heuristic scoring tables.
    """
    return FindingBead(
        id=_signal_id(signal),
        agent=agent,
        severity=_severity_for(signal),
        staleness_class=_staleness_for(signal),
        confidence=_confidence_for(signal),
        evidence_chain=list(signal.evidence),
        reasoning=_reasoning_for(signal),
        cycle_id=cycle_id,
        repo_path=repo_path,
        summary=_summary_for(signal),
    )
