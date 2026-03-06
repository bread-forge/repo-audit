"""Tests for the collector module."""

from pathlib import Path

from repo_audit.collector import CollectedArtifacts, harvest


def test_harvest_empty_dir(tmp_path: Path) -> None:
    """harvest on an empty directory returns a default CollectedArtifacts."""
    result = harvest(tmp_path)
    assert isinstance(result, CollectedArtifacts)
    assert result.readme is None
    assert result.claude_md is None
    assert result.specs == {}
    assert result.docs == {}
    assert result.entry_points == {}


def test_harvest_reads_readme(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")
    result = harvest(tmp_path)
    assert result.readme == "# Hello"


def test_harvest_reads_claude_md(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("instructions", encoding="utf-8")
    result = harvest(tmp_path)
    assert result.claude_md == "instructions"


def test_harvest_reads_specs(tmp_path: Path) -> None:
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "design.md").write_text("spec content", encoding="utf-8")
    result = harvest(tmp_path)
    assert "specs/design.md" in result.specs
    assert result.specs["specs/design.md"] == "spec content"


def test_harvest_reads_docs(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text("guide", encoding="utf-8")
    result = harvest(tmp_path)
    assert "docs/guide.md" in result.docs


def test_harvest_entry_points_no_pyproject(tmp_path: Path) -> None:
    result = harvest(tmp_path)
    assert result.entry_points == {}


def test_harvest_entry_points_with_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project.scripts]\nmycli = "mypackage:main"\n', encoding="utf-8"
    )
    result = harvest(tmp_path)
    assert result.entry_points == {"mycli": "mypackage:main"}


def test_harvest_docstrings(tmp_path: Path) -> None:
    py_file = tmp_path / "mod.py"
    py_file.write_text('"""Module docstring."""\n\nx = 1\n', encoding="utf-8")
    result = harvest(tmp_path)
    assert result.docstrings["mod.py"] == "Module docstring."


def test_harvest_docstrings_no_docstring(tmp_path: Path) -> None:
    py_file = tmp_path / "mod.py"
    py_file.write_text("x = 1\n", encoding="utf-8")
    result = harvest(tmp_path)
    assert result.docstrings["mod.py"] is None
