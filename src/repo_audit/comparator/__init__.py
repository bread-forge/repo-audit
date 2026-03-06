"""repo_audit.comparator — four-layer gap analysis between audit representations.

Public API
----------
- :class:`GapSignal` — dataclass holding a single detected gap.
- :func:`compare` — top-level entry point: given collected artifacts and an
  analysis result, return the combined list of :class:`GapSignal` instances
  from all four layers.
"""

from __future__ import annotations

from repo_audit.analyzer.result import AnalysisResult
from repo_audit.collector.artifacts import CollectedArtifacts
from repo_audit.comparator.gap_signal import GapSignal
from repo_audit.comparator.layers import (
    behavioral_vs_activated,
    declared_vs_structural,
    structural_vs_behavioral,
    test_vs_declared,
)

__all__ = ["GapSignal", "compare"]


def compare(
    artifacts: CollectedArtifacts,
    analysis: AnalysisResult,
) -> list[GapSignal]:
    """Run all four gap-analysis layers and return the combined signals.

    Layers are run in order:

    1. **declared vs structural** — modules present in the import graph but
       lacking module-level docstrings.
    2. **structural vs behavioral** — modules in the import graph that are
       unreachable from any entry point.
    3. **behavioral vs activated** — CLI entry points whose target module is
       absent from the import graph.
    4. **test vs declared** — spec Goals/Validation assertions that have no
       test-module coverage.

    Args:
        artifacts: Harvested collector artifacts (docs, specs, docstrings,
            entry points).
        analysis: Static analysis result (import graph, reachable modules).

    Returns:
        Combined list of :class:`GapSignal` instances from all layers, in
        layer order.
    """
    return [
        *declared_vs_structural(artifacts, analysis),
        *structural_vs_behavioral(analysis),
        *behavioral_vs_activated(artifacts, analysis),
        *test_vs_declared(artifacts, analysis),
    ]
