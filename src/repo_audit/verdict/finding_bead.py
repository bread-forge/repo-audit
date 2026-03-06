"""FindingBead dataclass — a scored, reasoned finding produced by the verdict module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low"]
StalenessClass = Literal["critical", "dependency", "structural", "architectural"]


@dataclass
class FindingBead:
    """A single audited finding with severity scoring and an evidence chain.

    Produced by :func:`~repo_audit.verdict.verdict` from a
    :class:`~repo_audit.comparator.gap_signal.GapSignal`.

    Attributes:
        id: Deterministic hex identifier derived from the originating signal.
        agent: Name of the agent that produced this finding.
        severity: Impact rating — one of ``critical``, ``high``, ``medium``, ``low``.
        staleness_class: Category of technical debt — one of ``critical``,
            ``dependency``, ``structural``, ``architectural``.
        confidence: Estimated reliability of the finding in the range [0, 1].
            Computed as ``min(len(evidence) * 0.2, 0.95)``.
        evidence_chain: Ordered list of evidence strings supporting the finding.
        reasoning: Human-readable paragraph explaining the finding and its context.
        cycle_id: Identifier of the audit cycle that produced this finding.
        repo_path: Filesystem path to the repository that was audited.
        summary: Short one-line description suitable for display in a table.
        reasoning_extended: Optional long-form LLM-generated explanation of the
            finding, populated by the enricher module after initial scoring.
        remediation_sketch: Optional suggested fix or remediation approach,
            populated by the enricher module after initial scoring.
        enrichment_cost_usd: Optional cost in USD of the LLM enrichment call
            that produced ``reasoning_extended`` and ``remediation_sketch``.
    """

    id: str
    agent: str
    severity: Severity
    staleness_class: StalenessClass
    confidence: float
    evidence_chain: list[str] = field(default_factory=list)
    reasoning: str = ""
    cycle_id: str = ""
    repo_path: str = ""
    summary: str = ""
    reasoning_extended: str | None = None
    remediation_sketch: str | None = None
    enrichment_cost_usd: float | None = None
