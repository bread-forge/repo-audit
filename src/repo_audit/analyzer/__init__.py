"""repo_audit.analyzer — static import-graph analysis for Python repositories.

Public API
----------
- :class:`AnalysisResult` — dataclass holding the import graph and reachable modules.
- :func:`analyze` — top-level entry point: given a repo path, return an
  ``AnalysisResult``.
"""

from __future__ import annotations

from pathlib import Path

from repo_audit.analyzer.ast_walker import find_python_files
from repo_audit.analyzer.import_graph import build_import_graph
from repo_audit.analyzer.reachability import compute_reachable, find_entry_points
from repo_audit.analyzer.result import AnalysisResult

__all__ = ["AnalysisResult", "analyze"]


def analyze(repo_path: Path) -> AnalysisResult:
    """Analyse the Python import structure of a repository.

    Steps performed:

    1. Scan all ``.py`` files under *repo_path*.
    2. Parse each file with :mod:`ast` to build a module→imported-modules graph.
    3. Identify entry points from ``pyproject.toml`` ``[project.scripts]`` and
       ``__main__.py`` files.
    4. BFS-trace reachability from those entry points through the import graph.

    For non-Python repositories (no ``.py`` files found), returns an
    :class:`AnalysisResult` with empty ``import_graph`` and
    ``reachable_from_entry_points``.

    Args:
        repo_path: Absolute or relative path to the root of the repository to
            analyse.  The path must exist and be a directory.

    Returns:
        :class:`AnalysisResult` populated with the import graph and the set of
        modules reachable from entry points.

    Raises:
        ValueError: If *repo_path* does not exist or is not a directory.
    """
    repo_path = Path(repo_path)
    if not repo_path.is_dir():
        raise ValueError(f"repo_path must be an existing directory: {repo_path!r}")

    if not find_python_files(repo_path):
        return AnalysisResult()

    import_graph = build_import_graph(repo_path)
    entry_points = find_entry_points(repo_path)
    reachable = compute_reachable(import_graph, entry_points)

    return AnalysisResult(
        import_graph=import_graph,
        reachable_from_entry_points=reachable,
    )
