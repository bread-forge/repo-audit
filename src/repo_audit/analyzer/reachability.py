"""Entry-point detection and reachability analysis via BFS over the import graph."""

from __future__ import annotations

import sys
from collections import deque
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


def find_entry_points(repo_path: Path) -> list[str]:
    """Identify Python entry-point modules in *repo_path*.

    Two sources are checked:

    1. ``pyproject.toml`` ``[project.scripts]`` — each value has the form
       ``"package.module:callable"``; the module portion is extracted.
    2. ``__main__.py`` files anywhere in the repository — these represent
       runnable packages (``python -m package``).

    Args:
        repo_path: Root of the repository to inspect.

    Returns:
        Deduplicated list of dotted module names that act as entry points.
        Order: pyproject scripts first, then ``__main__`` modules, each group
        sorted for determinism.
    """
    seen: set[str] = set()
    entry_points: list[str] = []

    for module in _entry_points_from_pyproject(repo_path):
        if module not in seen:
            seen.add(module)
            entry_points.append(module)

    for module in _entry_points_from_main_files(repo_path):
        if module not in seen:
            seen.add(module)
            entry_points.append(module)

    return entry_points


def _entry_points_from_pyproject(repo_path: Path) -> list[str]:
    """Extract entry-point module names from ``pyproject.toml``.

    Reads ``[project.scripts]`` and splits each ``"module:callable"`` value
    on the colon to get the module name.

    Returns an empty list when ``pyproject.toml`` is absent, cannot be parsed,
    or when ``tomllib`` is unavailable (Python < 3.11 without the backport).
    """
    if tomllib is None:
        return []

    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        return []

    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return []

    scripts: dict[str, str] = data.get("project", {}).get("scripts", {})
    modules: list[str] = []
    for target in sorted(scripts.values()):
        module_part = target.split(":")[0]
        if module_part:
            modules.append(module_part)
    return modules


def _entry_points_from_main_files(repo_path: Path) -> list[str]:
    """Return dotted module names for every ``__main__.py`` in *repo_path*.

    The module name is the package that owns the ``__main__.py``, resolved
    relative to the repository root (using the directory that directly
    contains the top-level package as the namespace base).

    For example, ``src/mypackage/__main__.py`` where ``src/`` is a src-layout
    root becomes ``mypackage.__main__``.
    """
    from repo_audit.analyzer.import_graph import (
        file_to_module_name,
        find_package_roots,
    )

    package_roots = find_package_roots(repo_path)

    modules: list[str] = []
    for main_file in sorted(repo_path.rglob("__main__.py")):
        module = _resolve_main_module(main_file, package_roots, repo_path)
        if module:
            modules.append(module)
    return modules


def _resolve_main_module(
    main_file: Path,
    package_roots: list[Path],
    repo_path: Path,
) -> str | None:
    """Convert a ``__main__.py`` path to a dotted module name, or None."""
    from repo_audit.analyzer.import_graph import file_to_module_name

    for root in package_roots:
        if main_file.is_relative_to(root):
            return file_to_module_name(main_file, root)
    # Standalone __main__.py at repo root (uncommon but valid).
    if main_file.parent == repo_path:
        return "__main__"
    return None


def compute_reachable(
    import_graph: dict[str, list[str]],
    entry_points: list[str],
) -> list[str]:
    """BFS over *import_graph* starting from *entry_points*.

    Collects every module reachable (directly or transitively) from at least
    one entry point.  Only modules that appear as keys in *import_graph* are
    considered part of the repository's own codebase; stdlib/third-party
    imports that do not appear as keys are included in the reachable set only
    when they are explicitly imported (they appear as values) so that callers
    know what is transitively pulled in, but they are not expanded further
    because they have no outgoing edges in the graph.

    Args:
        import_graph: ``{module: [imported_modules, ...]}`` mapping as
            produced by :func:`~repo_audit.analyzer.import_graph.build_import_graph`.
        entry_points: Starting modules for the traversal.

    Returns:
        Sorted list of all reachable module names (including entry points
        themselves if they appear in the graph).
    """
    visited: set[str] = set()
    queue: deque[str] = deque(entry_points)

    while queue:
        module = queue.popleft()
        if module in visited:
            continue
        visited.add(module)
        for imported in import_graph.get(module, []):
            if imported not in visited:
                queue.append(imported)

    return sorted(visited)
