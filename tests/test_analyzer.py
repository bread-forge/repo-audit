"""Tests for repo_audit.analyzer."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from repo_audit.analyzer import AnalysisResult, analyze
from repo_audit.analyzer.ast_walker import extract_imports, find_python_files
from repo_audit.analyzer.import_graph import (
    build_import_graph,
    file_to_module_name,
    find_package_roots,
)
from repo_audit.analyzer.reachability import compute_reachable, find_entry_points


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_file(base: Path, rel: str, content: str = "") -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------


def test_analysis_result_defaults():
    r = AnalysisResult()
    assert r.import_graph == {}
    assert r.reachable_from_entry_points == []


# ---------------------------------------------------------------------------
# find_python_files
# ---------------------------------------------------------------------------


def test_find_python_files_basic(tmp_path):
    write_file(tmp_path, "pkg/__init__.py")
    write_file(tmp_path, "pkg/mod.py")
    write_file(tmp_path, "__pycache__/cached.py")
    write_file(tmp_path, ".venv/lib/site.py")

    files = find_python_files(tmp_path)
    names = [f.name for f in files]
    assert "__init__.py" in names
    assert "mod.py" in names
    assert "cached.py" not in names
    assert "site.py" not in names


def test_find_python_files_empty(tmp_path):
    assert find_python_files(tmp_path) == []


# ---------------------------------------------------------------------------
# extract_imports
# ---------------------------------------------------------------------------


def test_extract_imports_absolute(tmp_path):
    src = write_file(tmp_path, "mod.py", """\
        import os
        import sys
        from pathlib import Path
    """)
    imports = extract_imports(src, "")
    assert "os" in imports
    assert "sys" in imports
    assert "pathlib" in imports


def test_extract_imports_relative(tmp_path):
    src = write_file(tmp_path, "pkg/sub/mod.py", """\
        from . import sibling
        from .. import parent_mod
        from .util import helper
    """)
    imports = extract_imports(src, "pkg.sub")
    # `from . import sibling` resolves to the current package "pkg.sub"
    assert "pkg.sub" in imports
    # `from .. import parent_mod` resolves to the parent package "pkg"
    assert "pkg" in imports
    # `from .util import helper` resolves to "pkg.sub.util"
    assert "pkg.sub.util" in imports


def test_extract_imports_syntax_error(tmp_path):
    src = write_file(tmp_path, "bad.py", "def (")
    assert extract_imports(src, "") == []


def test_extract_imports_deduplicates(tmp_path):
    src = write_file(tmp_path, "mod.py", """\
        import os
        import os
    """)
    imports = extract_imports(src, "")
    assert imports.count("os") == 1


# ---------------------------------------------------------------------------
# find_package_roots / file_to_module_name
# ---------------------------------------------------------------------------


def test_find_package_roots_src_layout(tmp_path):
    write_file(tmp_path, "src/mypkg/__init__.py")
    roots = find_package_roots(tmp_path)
    assert tmp_path / "src" in roots


def test_file_to_module_name_init(tmp_path):
    write_file(tmp_path, "src/mypkg/__init__.py")
    name = file_to_module_name(tmp_path / "src/mypkg/__init__.py", tmp_path / "src")
    assert name == "mypkg"


def test_file_to_module_name_submodule(tmp_path):
    root = tmp_path / "src"
    write_file(tmp_path, "src/mypkg/util.py")
    name = file_to_module_name(tmp_path / "src/mypkg/util.py", root)
    assert name == "mypkg.util"


# ---------------------------------------------------------------------------
# build_import_graph
# ---------------------------------------------------------------------------


def test_build_import_graph(tmp_path):
    write_file(tmp_path, "src/pkg/__init__.py", "")
    write_file(tmp_path, "src/pkg/a.py", "import os\nfrom pkg import b\n")
    write_file(tmp_path, "src/pkg/b.py", "import sys\n")

    graph = build_import_graph(tmp_path)
    assert "pkg.a" in graph
    assert "pkg.b" in graph
    assert "os" in graph["pkg.a"]
    assert "sys" in graph["pkg.b"]


# ---------------------------------------------------------------------------
# find_entry_points
# ---------------------------------------------------------------------------


def test_find_entry_points_main(tmp_path):
    write_file(tmp_path, "src/mypkg/__init__.py", "")
    write_file(tmp_path, "src/mypkg/__main__.py", "")

    eps = find_entry_points(tmp_path)
    assert any("__main__" in ep for ep in eps)


def test_find_entry_points_empty(tmp_path):
    assert find_entry_points(tmp_path) == []


# ---------------------------------------------------------------------------
# compute_reachable
# ---------------------------------------------------------------------------


def test_compute_reachable_basic():
    graph = {
        "a": ["b", "c"],
        "b": ["d"],
        "c": [],
        "d": [],
    }
    reachable = compute_reachable(graph, ["a"])
    assert sorted(reachable) == ["a", "b", "c", "d"]


def test_compute_reachable_cycle():
    graph = {"a": ["b"], "b": ["a"]}
    reachable = compute_reachable(graph, ["a"])
    assert sorted(reachable) == ["a", "b"]


def test_compute_reachable_no_entry_points():
    graph = {"a": ["b"], "b": []}
    assert compute_reachable(graph, []) == []


# ---------------------------------------------------------------------------
# analyze (integration)
# ---------------------------------------------------------------------------


def test_analyze_non_python_repo(tmp_path):
    result = analyze(tmp_path)
    assert result.import_graph == {}
    assert result.reachable_from_entry_points == []


def test_analyze_raises_on_missing_path(tmp_path):
    with pytest.raises(ValueError):
        analyze(tmp_path / "nonexistent")


def test_analyze_basic_repo(tmp_path):
    write_file(tmp_path, "src/mypkg/__init__.py", "")
    write_file(tmp_path, "src/mypkg/__main__.py", "from mypkg import core\n")
    write_file(tmp_path, "src/mypkg/core.py", "import os\n")

    result = analyze(tmp_path)
    assert isinstance(result, AnalysisResult)
    assert "mypkg.core" in result.import_graph
    assert len(result.reachable_from_entry_points) > 0
