"""Tests for repo_audit.analyzer.reachability."""

from __future__ import annotations

import textwrap
from pathlib import Path

from repo_audit.analyzer.import_graph import build_import_graph
from repo_audit.analyzer.reachability import (
    _entry_points_from_main_files,
    _entry_points_from_pyproject,
    _resolve_main_module,
    compute_reachable,
    find_entry_points,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


def write_py(base: Path, rel: str, content: str = "") -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _entry_points_from_pyproject
# ---------------------------------------------------------------------------


class TestEntryPointsFromPyproject:
    """Tests for _entry_points_from_pyproject."""

    def test_returns_empty_when_no_pyproject(self, tmp_path: Path) -> None:
        assert _entry_points_from_pyproject(tmp_path) == []

    def test_extracts_module_from_script_value(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\ncli = "mypkg.cli:main"\n')
        result = _entry_points_from_pyproject(tmp_path)
        assert "mypkg.cli" in result

    def test_extracts_multiple_scripts_sorted(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project.scripts]\nb = "pkg.b:run"\na = "pkg.a:run"\n'
        )
        result = _entry_points_from_pyproject(tmp_path)
        # Sorted by value: pkg.a comes before pkg.b
        assert result.index("pkg.a") < result.index("pkg.b")

    def test_returns_empty_for_malformed_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("not [ valid toml ]]]\n")
        assert _entry_points_from_pyproject(tmp_path) == []

    def test_returns_empty_when_no_scripts_table(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        assert _entry_points_from_pyproject(tmp_path) == []

    def test_skips_entry_without_colon(self, tmp_path: Path) -> None:
        """Script value with no colon still extracts the whole value as module."""
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\ncli = "mypkg"\n')
        result = _entry_points_from_pyproject(tmp_path)
        assert "mypkg" in result


# ---------------------------------------------------------------------------
# _entry_points_from_main_files
# ---------------------------------------------------------------------------


class TestEntryPointsFromMainFiles:
    """Tests for _entry_points_from_main_files."""

    def test_returns_empty_when_no_main_files(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py")
        assert _entry_points_from_main_files(tmp_path) == []

    def test_finds_main_in_src_layout(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "src/pkg/__main__.py")
        result = _entry_points_from_main_files(tmp_path)
        assert any("__main__" in m for m in result)

    def test_module_name_includes_package_prefix(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/__init__.py")
        write_py(tmp_path, "src/mypkg/__main__.py")
        result = _entry_points_from_main_files(tmp_path)
        assert "mypkg.__main__" in result

    def test_multiple_packages(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg_a/__init__.py")
        write_py(tmp_path, "src/pkg_a/__main__.py")
        write_py(tmp_path, "src/pkg_b/__init__.py")
        write_py(tmp_path, "src/pkg_b/__main__.py")
        result = _entry_points_from_main_files(tmp_path)
        assert "pkg_a.__main__" in result
        assert "pkg_b.__main__" in result


# ---------------------------------------------------------------------------
# _resolve_main_module
# ---------------------------------------------------------------------------


class TestResolveMainModule:
    """Tests for _resolve_main_module."""

    def test_resolves_src_layout_main(self, tmp_path: Path) -> None:
        from repo_audit.analyzer.import_graph import find_package_roots

        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "src/pkg/__main__.py")
        roots = find_package_roots(tmp_path)
        module = _resolve_main_module(tmp_path / "src/pkg/__main__.py", roots, tmp_path)
        assert module == "pkg.__main__"

    def test_standalone_main_at_repo_root(self, tmp_path: Path) -> None:
        """A __main__.py directly at the repo root → '__main__'."""
        main = tmp_path / "__main__.py"
        main.write_text("x = 1")
        module = _resolve_main_module(main, [], tmp_path)
        assert module == "__main__"

    def test_returns_none_for_unresolvable_main(self, tmp_path: Path) -> None:
        """A __main__.py in a directory not related to any package root → None."""
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "scripts/__main__.py")
        from repo_audit.analyzer.import_graph import find_package_roots

        roots = find_package_roots(tmp_path)
        module = _resolve_main_module(tmp_path / "scripts/__main__.py", roots, tmp_path)
        assert module is None


# ---------------------------------------------------------------------------
# find_entry_points
# ---------------------------------------------------------------------------


class TestFindEntryPoints:
    """Tests for find_entry_points."""

    def test_returns_empty_for_non_python_repo(self, tmp_path: Path) -> None:
        assert find_entry_points(tmp_path) == []

    def test_finds_main_in_src_layout(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/__init__.py", "")
        write_py(tmp_path, "src/mypkg/__main__.py", "")
        eps = find_entry_points(tmp_path)
        assert any("__main__" in ep for ep in eps)

    def test_finds_entry_points_from_pyproject(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/mypkg/__init__.py", "")
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\ncli = "mypkg.cli:main"\n')
        eps = find_entry_points(tmp_path)
        assert "mypkg.cli" in eps

    def test_deduplicates_overlapping_sources(self, tmp_path: Path) -> None:
        """When pyproject and __main__.py name the same module, it appears once."""
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/__main__.py", "")
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\ncli = "pkg.__main__:main"\n')
        eps = find_entry_points(tmp_path)
        assert eps.count("pkg.__main__") == 1

    def test_pyproject_entries_come_before_main_entries(self, tmp_path: Path) -> None:
        """Pyproject-derived entry points appear before __main__.py ones."""
        write_py(tmp_path, "src/pkg/__init__.py", "")
        write_py(tmp_path, "src/pkg/__main__.py", "")
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\ncli = "pkg.cli:main"\n')
        eps = find_entry_points(tmp_path)
        cli_idx = eps.index("pkg.cli")
        main_idx = eps.index("pkg.__main__")
        assert cli_idx < main_idx


# ---------------------------------------------------------------------------
# compute_reachable
# ---------------------------------------------------------------------------


class TestComputeReachable:
    """Tests for compute_reachable."""

    def test_basic_traversal(self) -> None:
        graph = {"a": ["b", "c"], "b": ["d"], "c": [], "d": []}
        assert compute_reachable(graph, ["a"]) == ["a", "b", "c", "d"]

    def test_cycle_does_not_loop_forever(self) -> None:
        graph = {"a": ["b"], "b": ["a"]}
        assert compute_reachable(graph, ["a"]) == ["a", "b"]

    def test_no_entry_points_returns_empty(self) -> None:
        graph = {"a": ["b"], "b": []}
        assert compute_reachable(graph, []) == []

    def test_entry_point_itself_is_included(self) -> None:
        graph = {"a": []}
        assert "a" in compute_reachable(graph, ["a"])

    def test_external_modules_included_when_imported(self) -> None:
        """stdlib/third-party imports not in the graph are still reachable."""
        graph = {"mymod": ["os", "sys"]}
        reachable = compute_reachable(graph, ["mymod"])
        assert "os" in reachable
        assert "sys" in reachable

    def test_external_modules_not_expanded(self) -> None:
        """External modules not in the graph stop BFS expansion."""
        graph = {"mymod": ["os"]}
        # "os" appears but has no edges in graph → only mymod and os are reachable
        reachable = compute_reachable(graph, ["mymod"])
        assert sorted(reachable) == ["mymod", "os"]

    def test_result_is_sorted(self) -> None:
        graph = {"c": ["a", "b"], "a": [], "b": []}
        reachable = compute_reachable(graph, ["c"])
        assert reachable == sorted(reachable)

    def test_multiple_entry_points(self) -> None:
        graph = {"a": ["x"], "b": ["y"], "x": [], "y": []}
        reachable = compute_reachable(graph, ["a", "b"])
        assert "a" in reachable
        assert "b" in reachable
        assert "x" in reachable
        assert "y" in reachable

    def test_disconnected_nodes_not_reachable(self) -> None:
        graph = {"a": ["b"], "b": [], "c": ["d"], "d": []}
        reachable = compute_reachable(graph, ["a"])
        assert "c" not in reachable
        assert "d" not in reachable


# ---------------------------------------------------------------------------
# find_entry_points + compute_reachable — fixture repo
# ---------------------------------------------------------------------------


class TestReachabilityFixtureRepo:
    """Integration tests using the sample_repo fixture."""

    def test_entry_points_contains_sample_main(self) -> None:
        eps = find_entry_points(FIXTURE_REPO)
        assert "sample.__main__" in eps

    def test_entry_points_deduplicated(self) -> None:
        """pyproject and __main__.py both resolve to sample.__main__; appears once."""
        eps = find_entry_points(FIXTURE_REPO)
        assert eps.count("sample.__main__") == 1

    def test_reachable_from_main_includes_core(self) -> None:
        graph = build_import_graph(FIXTURE_REPO)
        eps = find_entry_points(FIXTURE_REPO)
        reachable = compute_reachable(graph, eps)
        assert "sample.core" in reachable

    def test_reachable_from_main_includes_stdlib(self) -> None:
        """os and sys, imported by core.py, appear in the reachable set."""
        graph = build_import_graph(FIXTURE_REPO)
        eps = find_entry_points(FIXTURE_REPO)
        reachable = compute_reachable(graph, eps)
        assert "os" in reachable
        assert "sys" in reachable

    def test_all_sample_modules_reachable(self) -> None:
        graph = build_import_graph(FIXTURE_REPO)
        eps = find_entry_points(FIXTURE_REPO)
        reachable = compute_reachable(graph, eps)
        assert "sample.__main__" in reachable
        assert "sample.core" in reachable
