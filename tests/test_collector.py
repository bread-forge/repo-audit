"""Tests for the collector module."""

from __future__ import annotations

from pathlib import Path

import pytest

from repo_audit.collector import CollectedArtifacts, harvest
from repo_audit.collector.harvester import (
    _collect_glob_markdown,
    _collect_specs_markdown,
    _extract_module_docstrings,
    _parse_entry_points,
    _read_optional_file,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


# ---------------------------------------------------------------------------
# CollectedArtifacts dataclass
# ---------------------------------------------------------------------------


class TestCollectedArtifacts:
    """Tests for the CollectedArtifacts dataclass defaults and field types."""

    def test_defaults(self) -> None:
        """All fields default to empty/None without arguments."""
        a = CollectedArtifacts()
        assert a.readme is None
        assert a.claude_md is None
        assert a.specs == {}
        assert a.docs == {}
        assert a.docstrings == {}
        assert a.entry_points == {}

    def test_fields_accept_values(self) -> None:
        """Fields accept the correct types."""
        a = CollectedArtifacts(
            readme="# Readme",
            claude_md="instructions",
            specs={"specs/s.md": "spec"},
            docs={"docs/d.md": "doc"},
            docstrings={"mod.py": "docstring", "empty.py": None},
            entry_points={"cli": "pkg:main"},
        )
        assert a.readme == "# Readme"
        assert a.specs == {"specs/s.md": "spec"}
        assert a.docstrings["empty.py"] is None
        assert a.entry_points == {"cli": "pkg:main"}


# ---------------------------------------------------------------------------
# _read_optional_file
# ---------------------------------------------------------------------------


class TestReadOptionalFile:
    """Tests for _read_optional_file."""

    def test_returns_content_when_file_exists(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello", encoding="utf-8")
        assert _read_optional_file(f) == "hello"

    def test_returns_none_when_file_absent(self, tmp_path: Path) -> None:
        assert _read_optional_file(tmp_path / "missing.txt") is None

    def test_returns_none_for_directory(self, tmp_path: Path) -> None:
        """A directory path is not a file; should return None."""
        assert _read_optional_file(tmp_path) is None


# ---------------------------------------------------------------------------
# _collect_specs_markdown
# ---------------------------------------------------------------------------


class TestCollectSpecsMarkdown:
    """Tests for _collect_specs_markdown (non-recursive, top-level only)."""

    def test_empty_when_directory_absent(self, tmp_path: Path) -> None:
        assert _collect_specs_markdown(tmp_path / "specs", tmp_path) == {}

    def test_collects_top_level_md_files(self, tmp_path: Path) -> None:
        specs = tmp_path / "specs"
        specs.mkdir()
        (specs / "a.md").write_text("aaa", encoding="utf-8")
        (specs / "b.md").write_text("bbb", encoding="utf-8")
        result = _collect_specs_markdown(specs, tmp_path)
        assert result == {"specs/a.md": "aaa", "specs/b.md": "bbb"}

    def test_does_not_recurse_into_subdirectories(self, tmp_path: Path) -> None:
        specs = tmp_path / "specs"
        (specs / "sub").mkdir(parents=True)
        (specs / "top.md").write_text("top", encoding="utf-8")
        (specs / "sub" / "nested.md").write_text("nested", encoding="utf-8")
        result = _collect_specs_markdown(specs, tmp_path)
        assert "specs/top.md" in result
        assert "specs/sub/nested.md" not in result

    def test_ignores_non_md_files(self, tmp_path: Path) -> None:
        specs = tmp_path / "specs"
        specs.mkdir()
        (specs / "spec.md").write_text("md", encoding="utf-8")
        (specs / "spec.txt").write_text("txt", encoding="utf-8")
        result = _collect_specs_markdown(specs, tmp_path)
        assert list(result.keys()) == ["specs/spec.md"]

    def test_keys_are_posix_paths_relative_to_repo_root(self, tmp_path: Path) -> None:
        specs = tmp_path / "specs"
        specs.mkdir()
        (specs / "design.md").write_text("x", encoding="utf-8")
        result = _collect_specs_markdown(specs, tmp_path)
        assert "specs/design.md" in result


# ---------------------------------------------------------------------------
# _collect_glob_markdown
# ---------------------------------------------------------------------------


class TestCollectGlobMarkdown:
    """Tests for _collect_glob_markdown (recursive)."""

    def test_empty_when_directory_absent(self, tmp_path: Path) -> None:
        assert _collect_glob_markdown(tmp_path / "docs", tmp_path) == {}

    def test_collects_recursively(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        (docs / "sub").mkdir(parents=True)
        (docs / "top.md").write_text("top", encoding="utf-8")
        (docs / "sub" / "deep.md").write_text("deep", encoding="utf-8")
        result = _collect_glob_markdown(docs, tmp_path)
        assert "docs/top.md" in result
        assert "docs/sub/deep.md" in result

    def test_ignores_non_md_files(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "guide.md").write_text("guide", encoding="utf-8")
        (docs / "guide.rst").write_text("rst", encoding="utf-8")
        result = _collect_glob_markdown(docs, tmp_path)
        assert "docs/guide.md" in result
        assert not any(k.endswith(".rst") for k in result)


# ---------------------------------------------------------------------------
# _parse_entry_points
# ---------------------------------------------------------------------------


class TestParseEntryPoints:
    """Tests for _parse_entry_points."""

    def test_returns_empty_when_no_pyproject(self, tmp_path: Path) -> None:
        assert _parse_entry_points(tmp_path) == {}

    def test_returns_empty_when_no_scripts_table(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        assert _parse_entry_points(tmp_path) == {}

    def test_parses_scripts_table(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text('[project.scripts]\nmycli = "mypackage:main"\n')
        assert _parse_entry_points(tmp_path) == {"mycli": "mypackage:main"}

    def test_returns_empty_on_malformed_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("not [ valid toml ]]]\n")
        assert _parse_entry_points(tmp_path) == {}

    def test_returns_multiple_scripts(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project.scripts]\na = "pkg.a:run"\nb = "pkg.b:run"\n'
        )
        result = _parse_entry_points(tmp_path)
        assert result == {"a": "pkg.a:run", "b": "pkg.b:run"}


# ---------------------------------------------------------------------------
# _extract_module_docstrings
# ---------------------------------------------------------------------------


class TestExtractModuleDocstrings:
    """Tests for _extract_module_docstrings."""

    def test_extracts_module_docstring(self, tmp_path: Path) -> None:
        (tmp_path / "mod.py").write_text('"""My module."""\nx = 1\n')
        result = _extract_module_docstrings(tmp_path)
        assert result["mod.py"] == "My module."

    def test_none_when_no_docstring(self, tmp_path: Path) -> None:
        (tmp_path / "mod.py").write_text("x = 1\n")
        assert _extract_module_docstrings(tmp_path)["mod.py"] is None

    def test_none_on_syntax_error(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("def (")
        assert _extract_module_docstrings(tmp_path)["bad.py"] is None

    def test_keys_are_posix_relative_paths(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text('"""pkg"""')
        result = _extract_module_docstrings(tmp_path)
        assert "pkg/__init__.py" in result


# ---------------------------------------------------------------------------
# harvest — unit tests with tmp_path
# ---------------------------------------------------------------------------


class TestHarvestBasic:
    """Unit tests for harvest() using manually constructed tmp directories."""

    def test_harvest_empty_dir(self, tmp_path: Path) -> None:
        """harvest on an empty directory returns a default CollectedArtifacts."""
        result = harvest(tmp_path)
        assert isinstance(result, CollectedArtifacts)
        assert result.readme is None
        assert result.claude_md is None
        assert result.specs == {}
        assert result.docs == {}
        assert result.entry_points == {}

    def test_harvest_reads_readme(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")
        assert harvest(tmp_path).readme == "# Hello"

    def test_harvest_reads_claude_md(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("instructions", encoding="utf-8")
        assert harvest(tmp_path).claude_md == "instructions"

    def test_harvest_reads_specs(self, tmp_path: Path) -> None:
        specs = tmp_path / "specs"
        specs.mkdir()
        (specs / "design.md").write_text("spec content", encoding="utf-8")
        result = harvest(tmp_path)
        assert "specs/design.md" in result.specs
        assert result.specs["specs/design.md"] == "spec content"

    def test_harvest_reads_docs(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "guide.md").write_text("guide", encoding="utf-8")
        assert "docs/guide.md" in harvest(tmp_path).docs

    def test_harvest_entry_points_no_pyproject(self, tmp_path: Path) -> None:
        assert harvest(tmp_path).entry_points == {}

    def test_harvest_entry_points_with_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project.scripts]\nmycli = "mypackage:main"\n', encoding="utf-8"
        )
        assert harvest(tmp_path).entry_points == {"mycli": "mypackage:main"}

    def test_harvest_docstrings(self, tmp_path: Path) -> None:
        (tmp_path / "mod.py").write_text('"""Module docstring."""\n\nx = 1\n', encoding="utf-8")
        assert harvest(tmp_path).docstrings["mod.py"] == "Module docstring."

    def test_harvest_docstrings_no_docstring(self, tmp_path: Path) -> None:
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        assert harvest(tmp_path).docstrings["mod.py"] is None

    def test_harvest_does_not_recurse_specs(self, tmp_path: Path) -> None:
        """Specs are collected only one level deep, not recursively."""
        specs = tmp_path / "specs"
        (specs / "sub").mkdir(parents=True)
        (specs / "top.md").write_text("top")
        (specs / "sub" / "nested.md").write_text("nested")
        result = harvest(tmp_path)
        assert "specs/top.md" in result.specs
        assert "specs/sub/nested.md" not in result.specs

    def test_harvest_recurses_docs(self, tmp_path: Path) -> None:
        """Docs are collected recursively through all subdirectories."""
        docs = tmp_path / "docs"
        (docs / "sub").mkdir(parents=True)
        (docs / "index.md").write_text("index")
        (docs / "sub" / "page.md").write_text("page")
        result = harvest(tmp_path)
        assert "docs/index.md" in result.docs
        assert "docs/sub/page.md" in result.docs


# ---------------------------------------------------------------------------
# harvest — fixture repo integration tests
# ---------------------------------------------------------------------------


class TestHarvestFixtureRepo:
    """Integration tests: harvest the sample_repo fixture and assert structure."""

    @pytest.fixture(scope="class")
    def artifacts(self) -> CollectedArtifacts:
        return harvest(FIXTURE_REPO)

    def test_readme_is_present(self, artifacts: CollectedArtifacts) -> None:
        assert artifacts.readme is not None
        assert "Sample Repository" in artifacts.readme

    def test_claude_md_is_absent(self, artifacts: CollectedArtifacts) -> None:
        """The fixture repo has no CLAUDE.md file."""
        assert artifacts.claude_md is None

    def test_specs_contains_sample_spec(self, artifacts: CollectedArtifacts) -> None:
        assert "specs/sample_spec.md" in artifacts.specs
        assert "Sample Specification" in artifacts.specs["specs/sample_spec.md"]

    def test_docs_is_empty(self, artifacts: CollectedArtifacts) -> None:
        """The fixture repo has no docs/ directory."""
        assert artifacts.docs == {}

    def test_entry_points_from_pyproject(self, artifacts: CollectedArtifacts) -> None:
        assert "sample-run" in artifacts.entry_points
        assert artifacts.entry_points["sample-run"] == "sample.__main__:main"

    def test_docstrings_cover_all_py_files(self, artifacts: CollectedArtifacts) -> None:
        """All three .py files in the fixture should appear in docstrings."""
        keys = set(artifacts.docstrings.keys())
        assert any(k.endswith("__init__.py") for k in keys)
        assert any(k.endswith("__main__.py") for k in keys)
        assert any(k.endswith("core.py") for k in keys)

    def test_init_docstring(self, artifacts: CollectedArtifacts) -> None:
        init_key = next(k for k in artifacts.docstrings if k.endswith("__init__.py"))
        assert artifacts.docstrings[init_key] == "Sample package for repo-audit integration tests."

    def test_core_docstring(self, artifacts: CollectedArtifacts) -> None:
        core_key = next(k for k in artifacts.docstrings if k.endswith("core.py"))
        assert artifacts.docstrings[core_key] == "Core computation logic for the sample package."

    def test_main_docstring(self, artifacts: CollectedArtifacts) -> None:
        main_key = next(k for k in artifacts.docstrings if k.endswith("__main__.py"))
        assert artifacts.docstrings[main_key] == "Entry point for the sample package."

    def test_all_artifact_types_present(self, artifacts: CollectedArtifacts) -> None:
        """Fixture repo exercises every artifact field: readme, specs, entry_points, docstrings."""
        assert artifacts.readme is not None
        assert len(artifacts.specs) > 0
        assert len(artifacts.entry_points) > 0
        assert len(artifacts.docstrings) > 0
