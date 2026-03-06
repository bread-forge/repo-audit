"""Build a module-to-imported-modules graph from a Python repository."""

from __future__ import annotations

from pathlib import Path

from repo_audit.analyzer.ast_walker import extract_imports, find_python_files


def find_package_roots(repo_path: Path) -> list[Path]:
    """Find the root directories that contain top-level Python packages.

    A package root is a directory that directly contains a sub-directory
    with an ``__init__.py``, but does not itself have an ``__init__.py``
    (i.e. it is not itself a package).

    Common examples: the repo root, or a ``src/`` layout directory.

    Args:
        repo_path: Root of the repository to inspect.

    Returns:
        Deduplicated list of package-root directories.
    """
    roots: set[Path] = set()
    for init_file in repo_path.rglob("__init__.py"):
        pkg_dir = init_file.parent
        # Walk upward to find the topmost package directory in this chain.
        while (pkg_dir.parent / "__init__.py").exists():
            pkg_dir = pkg_dir.parent
        # The parent of the top-level package directory is the package root.
        roots.add(pkg_dir.parent)
    return list(roots)


def file_to_module_name(file_path: Path, package_root: Path) -> str:
    """Convert a .py file path to its dotted module name.

    Args:
        file_path: Absolute path to a .py source file.
        package_root: The package-root directory (e.g. ``src/`` or the repo
            root) that acts as the namespace base.

    Returns:
        Dotted module name (e.g. ``"repo_audit.analyzer.result"``).
        For ``__init__.py``, returns the package name without the file stem.
    """
    rel = file_path.relative_to(package_root)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _package_of_module(module_name: str) -> str:
    """Return the package portion of a dotted module name.

    For ``"foo.bar.baz"`` returns ``"foo.bar"``.
    For ``"foo"`` (top-level) returns ``""``.
    """
    dot = module_name.rfind(".")
    return module_name[:dot] if dot != -1 else ""


def build_import_graph(repo_path: Path) -> dict[str, list[str]]:
    """Walk all Python files in *repo_path* and build an import graph.

    The graph maps each module's dotted name to the list of top-level dotted
    module names it imports (absolute and relative imports both resolved).

    Files that cannot be parsed (syntax errors, encoding issues) contribute
    an empty import list rather than causing a failure.

    Args:
        repo_path: Root of the repository to analyse.

    Returns:
        ``{module_name: [imported_module, ...]}`` mapping.  Every source file
        found appears as a key; if it has no imports its value is ``[]``.
    """
    package_roots = find_package_roots(repo_path)

    # Build a mapping: absolute path → (module_name, current_package)
    # We keep the first root match for each file (roots are deduplicated).
    file_module_map: dict[Path, tuple[str, str]] = {}
    for py_file in find_python_files(repo_path):
        module_name = _module_name_for_file(py_file, package_roots, repo_path)
        current_package = _package_of_module(module_name)
        file_module_map[py_file] = (module_name, current_package)

    graph: dict[str, list[str]] = {}
    for py_file, (module_name, current_package) in file_module_map.items():
        imports = extract_imports(py_file, current_package)
        graph[module_name] = imports

    return graph


def _module_name_for_file(
    file_path: Path,
    package_roots: list[Path],
    repo_path: Path,
) -> str:
    """Determine the best dotted module name for *file_path*.

    Prefers a package-root-relative name when the file lives inside a known
    package; falls back to a repo-root-relative name for standalone scripts.

    Args:
        file_path: .py file to name.
        package_roots: Candidate package-root directories.
        repo_path: Repository root used as the fallback base.

    Returns:
        Dotted module name string.
    """
    for root in package_roots:
        if file_path.is_relative_to(root):
            return file_to_module_name(file_path, root)
    # Fallback for standalone scripts not inside any package.
    return file_to_module_name(file_path, repo_path)
