"""repo_audit.verdict — converts GapSignals into scored FindingBeads.

Public API
----------
- :class:`FindingBead` — dataclass holding a single scored finding.
- :func:`verdict` — top-level entry point: given a list of
  :class:`~repo_audit.comparator.gap_signal.GapSignal` instances, return a
  list of :class:`FindingBead` instances with severity, staleness class,
  confidence, evidence chain, and reasoning populated.
"""

from __future__ import annotations

from repo_audit.comparator.gap_signal import GapSignal
from repo_audit.verdict.finding_bead import FindingBead
from repo_audit.verdict.scorer import score_signal

__all__ = ["FindingBead", "verdict"]


def verdict(
    signals: list[GapSignal],
    cycle_id: str = "",
    repo_path: str = "",
    agent: str = "repo-audit",
) -> list[FindingBead]:
    """Score a list of gap signals and return the corresponding findings.

    Each :class:`~repo_audit.comparator.gap_signal.GapSignal` is scored
    independently via :func:`~repo_audit.verdict.scorer.score_signal`.  The
    output order mirrors the input order.

    Args:
        signals: Gap signals produced by the comparator module.
        cycle_id: Optional identifier for the current audit cycle; threaded
            through to every :class:`FindingBead`.
        repo_path: Optional filesystem path to the audited repository; threaded
            through to every :class:`FindingBead`.
        agent: Name of the agent performing the verdict.  Defaults to
            ``"repo-audit"``.

    Returns:
        One :class:`FindingBead` per input signal, in the same order.
    """
    return [
        score_signal(signal, cycle_id=cycle_id, repo_path=repo_path, agent=agent)
        for signal in signals
    ]
