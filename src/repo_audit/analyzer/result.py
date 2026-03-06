"""AnalysisResult dataclass for the repo-audit analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    """Result of analyzing a repository's Python import structure.

    Attributes:
        import_graph: Maps each module name to the list of modules it imports.
            Module names use dotted notation (e.g. "repo_audit.analyzer.result").
        reachable_from_entry_points: Sorted list of all modules reachable
            (directly or transitively) from the repository's entry points.
    """

    import_graph: dict[str, list[str]] = field(default_factory=dict)
    reachable_from_entry_points: list[str] = field(default_factory=list)
