"""AST-based walker for extracting imports from Python source files."""

from __future__ import annotations

import ast
from pathlib import Path


class ImportExtractor(ast.NodeVisitor):
    """Collects all imported module names from an AST."""

    def __init__(self, current_package: str) -> None:
        self._current_package = current_package
        self.imported_modules: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imported_modules.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0:
            # Absolute import: `from foo.bar import baz`
            if node.module:
                self.imported_modules.append(node.module)
        else:
            # Relative import: `from . import baz` or `from ..foo import bar`
            resolved = _resolve_relative_import(
                node.module, node.level, self._current_package
            )
            if resolved:
                self.imported_modules.append(resolved)


def _resolve_relative_import(
    module: str | None, level: int, current_package: str
) -> str | None:
    """Resolve a relative import to an absolute dotted module name.

    Args:
        module: The module part of the import (e.g. "bar" in `from .bar import x`),
            or None for `from . import x`.
        level: Number of dots (1 = current package, 2 = parent package, etc.).
        current_package: Dotted package name of the file performing the import
            (e.g. "repo_audit.analyzer" for a file in that package).

    Returns:
        Absolute dotted module name, or None if the package is too shallow for
        the given level.
    """
    parts = current_package.split(".") if current_package else []
    # Drop (level - 1) trailing package components to climb the hierarchy.
    # level=1 stays in the current package; level=2 goes to its parent, etc.
    ancestor_depth = level - 1
    if ancestor_depth > len(parts):
        return None
    ancestor_parts = parts[: len(parts) - ancestor_depth] if ancestor_depth else parts
    if module:
        return ".".join(ancestor_parts + [module])
    return ".".join(ancestor_parts) or None


def extract_imports(source_path: Path, current_package: str) -> list[str]:
    """Parse a Python file and return all imported module names.

    Handles absolute and relative imports. Syntax errors are silently ignored
    (the file is treated as having no imports).

    Args:
        source_path: Path to the .py file to parse.
        current_package: Dotted package name of the file (used to resolve
            relative imports). Pass an empty string for top-level scripts.

    Returns:
        Deduplicated list of imported module names in dotted notation.
    """
    try:
        source = source_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(source_path))
    except SyntaxError:
        return []

    extractor = ImportExtractor(current_package)
    extractor.visit(tree)

    seen: set[str] = set()
    unique: list[str] = []
    for name in extractor.imported_modules:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def find_python_files(repo_path: Path) -> list[Path]:
    """Return all .py files under *repo_path*, excluding common non-source dirs.

    Skips hidden directories (starting with '.') and virtual-environment
    directories (``venv``, ``.venv``, ``__pycache__``, ``node_modules``).

    Args:
        repo_path: Root of the repository to scan.

    Returns:
        Sorted list of .py file paths.
    """
    EXCLUDED_DIRS = {".venv", "venv", ".env", "__pycache__", "node_modules", ".git"}

    results: list[Path] = []
    for path in repo_path.rglob("*.py"):
        # Reject if any component of the path is an excluded directory name.
        if any(part in EXCLUDED_DIRS or part.startswith(".") for part in path.parts[len(repo_path.parts):- 1]):
            continue
        results.append(path)
    results.sort()
    return results
