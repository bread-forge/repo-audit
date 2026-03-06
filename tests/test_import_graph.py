"""Tests for repo_audit.analyzer.import_graph."""

from __future__ import annotations

import textwrap
from pathlib import Path

from repo_audit.analyzer.import_graph import (
    _module_name_for_file,
    _package_of_module,
    build_import_graph,
    file_to_module_name,
    find_package_roots,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


def write_py(base: Path, rel: str, content: str = "") -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _package_of_module
# ---------------------------------------------------------------------------


class TestPackageOfModule:
    """Tests for _package_of_module internal helper."""

    def test_nested_module(self) -> None:
        assert _package_of_module("foo.bar.baz") == "foo.bar"

    def test_single_level_package(self) -> None:
        assert _package_of_module("foo.bar") == "foo"

    def test_top_level_module_returns_empty(self) -> None:
        assert _package_of_module("foo") == ""

    def test_empty_string(self) -> None:
        assert _package_of_module("") == ""

    def test_deeply_nested(self) -> None:
        assert _package_of_module("a.b.c.d.e") == "a.b.c.d"


# ---------------------------------------------------------------------------
# file_to_module_name
# ---------------------------------------------------------------------------


class TestFileToModuleName:
    """Tests for file_to_module_name."""

    def test_init_file_drops_init_stem(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/__init__.py")
        name = file_to_module_name(tmp_path / "src/mypkg/__init__.py", tmp_path / "src")
        assert name == "mypkg"

    def test_regular_module(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/util.py")
        name = file_to_module_name(tmp_path / "src/mypkg/util.py", tmp_path / "src")
        assert name == "mypkg.util"

    def test_nested_subpackage(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/sub/mod.py")
        name = file_to_module_name(tmp_path / "src/pkg/sub/mod.py", tmp_path / "src")
        assert name == "pkg.sub.mod"

    def test_main_module(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__main__.py")
        name = file_to_module_name(tmp_path / "src/pkg/__main__.py", tmp_path / "src")
        assert name == "pkg.__main__"

    def test_top_level_script(self, tmp_path: Path) -> None:
        write_py(tmp_path, "script.py")
        name = file_to_module_name(tmp_path / "script.py", tmp_path)
        assert name == "script"


# ---------------------------------------------------------------------------
# find_package_roots
# ---------------------------------------------------------------------------


class TestFindPackageRoots:
    """Tests for find_package_roots."""

    def test_src_layout(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/__init__.py")
        roots = find_package_roots(tmp_path)
        assert tmp_path / "src" in roots

    def test_flat_layout(self, tmp_path: Path) -> None:
        write_py(tmp_path, "mypkg/__init__.py")
        roots = find_package_roots(tmp_path)
        assert tmp_path in roots

    def test_multiple_packages_same_root(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg_a/__init__.py")
        write_py(tmp_path, "src/pkg_b/__init__.py")
        roots = find_package_roots(tmp_path)
        # Both packages live under src/, so only one root
        assert tmp_path / "src" in roots

    def test_no_packages_returns_empty(self, tmp_path: Path) -> None:
        """No __init__.py means no package roots discovered."""
        (tmp_path / "script.py").write_text("x = 1")
        assert find_package_roots(tmp_path) == []

    def test_nested_package_only_returns_top_level_root(self, tmp_path: Path) -> None:
        """Only the package root (parent of the top-level pkg) is returned."""
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "src/pkg/sub/__init__.py")
        roots = find_package_roots(tmp_path)
        assert tmp_path / "src" in roots
        # src/pkg should NOT be in roots (it's a package, not a root)
        assert tmp_path / "src" / "pkg" not in roots


# ---------------------------------------------------------------------------
# _module_name_for_file
# ---------------------------------------------------------------------------


class TestModuleNameForFile:
    """Tests for _module_name_for_file."""

    def test_prefers_package_root_over_repo_root(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "src/pkg/mod.py")
        roots = find_package_roots(tmp_path)
        name = _module_name_for_file(tmp_path / "src/pkg/mod.py", roots, tmp_path)
        assert name == "pkg.mod"

    def test_falls_back_to_repo_root_for_standalone_script(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "standalone.py")
        roots = find_package_roots(tmp_path)
        name = _module_name_for_file(tmp_path / "standalone.py", roots, tmp_path)
        assert name == "standalone"

    def test_empty_roots_uses_repo_root(self, tmp_path: Path) -> None:
        write_py(tmp_path, "script.py")
        name = _module_name_for_file(tmp_path / "script.py", [], tmp_path)
        assert name == "script"


# ---------------------------------------------------------------------------
# build_import_graph
# ---------------------------------------------------------------------------


class TestBuildImportGraph:
    """Tests for build_import_graph."""

    def test_basic_graph_structure(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/a.py", "import os\nfrom pkg import b\n")
        write_py(tmp_path, "src/pkg/b.py", "import sys\n")
        graph = build_import_graph(tmp_path)
        assert "pkg.a" in graph
        assert "pkg.b" in graph
        assert "os" in graph["pkg.a"]
        assert "sys" in graph["pkg.b"]

    def test_every_file_appears_as_key(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/mod.py", "")
        graph = build_import_graph(tmp_path)
        assert "pkg" in graph
        assert "pkg.mod" in graph

    def test_no_imports_yields_empty_list(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py", "")
        graph = build_import_graph(tmp_path)
        assert graph["pkg"] == []

    def test_empty_repo_returns_empty_graph(self, tmp_path: Path) -> None:
        graph = build_import_graph(tmp_path)
        assert graph == {}

    def test_syntax_error_yields_empty_imports(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/bad.py", "def (")
        graph = build_import_graph(tmp_path)
        assert graph.get("pkg.bad") == []

    def test_relative_imports_resolved(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/a.py", "from . import b\n")
        write_py(tmp_path, "src/pkg/b.py", "")
        graph = build_import_graph(tmp_path)
        # from . import b in pkg.a → resolves to "pkg"
        assert "pkg" in graph["pkg.a"]


# ---------------------------------------------------------------------------
# build_import_graph — fixture repo
# ---------------------------------------------------------------------------


class TestBuildImportGraphFixtureRepo:
    """Integration tests for build_import_graph on the sample_repo fixture."""

    def test_all_modules_present_as_keys(self) -> None:
        graph = build_import_graph(FIXTURE_REPO)
        assert "sample" in graph
        assert "sample.__main__" in graph
        assert "sample.core" in graph

    def test_core_imports_os_and_sys(self) -> None:
        graph = build_import_graph(FIXTURE_REPO)
        assert "os" in graph["sample.core"]
        assert "sys" in graph["sample.core"]

    def test_main_imports_core(self) -> None:
        """__main__.py imports from .core which resolves to sample.core."""
        graph = build_import_graph(FIXTURE_REPO)
        assert "sample.core" in graph["sample.__main__"]

    def test_init_has_no_imports(self) -> None:
        graph = build_import_graph(FIXTURE_REPO)
        assert graph["sample"] == []

    def test_graph_has_exactly_three_keys(self) -> None:
        """The fixture has exactly three .py files → three graph keys."""
        graph = build_import_graph(FIXTURE_REPO)
        assert len(graph) == 3
