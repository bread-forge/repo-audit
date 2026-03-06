"""Harvest repository artifacts into a CollectedArtifacts instance."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-reuse-declared-attr]

from .artifacts import CollectedArtifacts


def _read_optional_file(path: Path) -> Optional[str]:
    """Return the text content of *path*, or None if the file does not exist."""
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None


def _collect_glob_markdown(directory: Path, repo_root: Path) -> dict[str, str]:
    """Read all .md files under *directory* (recursively).

    Keys are POSIX paths relative to *repo_root*.  Files that cannot be read
    (permissions, encoding errors) are silently skipped.
    """
    result: dict[str, str] = {}
    if not directory.is_dir():
        return result
    for md_file in sorted(directory.rglob("*.md")):
        key = md_file.relative_to(repo_root).as_posix()
        try:
            result[key] = md_file.read_text(encoding="utf-8")
        except OSError:
            pass
    return result


def _collect_specs_markdown(specs_dir: Path, repo_root: Path) -> dict[str, str]:
    """Read all .md files directly inside *specs_dir* (non-recursive).

    Keys are POSIX paths relative to *repo_root*.
    """
    result: dict[str, str] = {}
    if not specs_dir.is_dir():
        return result
    for md_file in sorted(specs_dir.glob("*.md")):
        key = md_file.relative_to(repo_root).as_posix()
        try:
            result[key] = md_file.read_text(encoding="utf-8")
        except OSError:
            pass
    return result


def _parse_entry_points(repo_root: Path) -> dict[str, str]:
    """Return the [project.scripts] table from pyproject.toml.

    Returns an empty dict when pyproject.toml is absent, malformed, or has no
    [project.scripts] table.
    """
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.is_file():
        return {}
    try:
        with pyproject_path.open("rb") as fh:
            data = tomllib.load(fh)
        scripts = data.get("project", {}).get("scripts", {})
        return {str(k): str(v) for k, v in scripts.items()}
    except Exception:  # noqa: BLE001 — treat any parse failure as empty
        return {}


def _extract_module_docstrings(repo_root: Path) -> dict[str, Optional[str]]:
    """Extract module-level docstrings from every .py file under *repo_root*.

    Uses :func:`ast.parse` so no code is executed.  Files with syntax errors or
    I/O problems map to None.  Keys are POSIX paths relative to *repo_root*.
    """
    result: dict[str, Optional[str]] = {}
    for py_file in sorted(repo_root.rglob("*.py")):
        key = py_file.relative_to(repo_root).as_posix()
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=key)
            result[key] = ast.get_docstring(tree)
        except (OSError, SyntaxError):
            result[key] = None
    return result


def harvest(repo_path: Path) -> CollectedArtifacts:
    """Collect all auditable artifacts from a repository directory.

    Reads the following without executing any repository code:

    * ``README.md`` at the repo root
    * ``CLAUDE.md`` at the repo root
    * ``specs/*.md`` (one level deep)
    * ``docs/**/*.md`` (recursive)
    * ``[project.scripts]`` entries from ``pyproject.toml``
    * Module-level docstrings from every ``.py`` file (via :mod:`ast`)

    Args:
        repo_path: Absolute or relative path to the repository root.

    Returns:
        A :class:`CollectedArtifacts` instance populated with all discovered
        content.
    """
    root = Path(repo_path)

    return CollectedArtifacts(
        readme=_read_optional_file(root / "README.md"),
        claude_md=_read_optional_file(root / "CLAUDE.md"),
        specs=_collect_specs_markdown(root / "specs", root),
        docs=_collect_glob_markdown(root / "docs", root),
        entry_points=_parse_entry_points(root),
        docstrings=_extract_module_docstrings(root),
    )
