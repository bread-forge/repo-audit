"""Tests for repo_audit.analyzer.ast_walker."""

from __future__ import annotations

import textwrap
from pathlib import Path

from repo_audit.analyzer.ast_walker import (
    ImportExtractor,
    _resolve_relative_import,
    extract_imports,
    find_python_files,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


def write_py(base: Path, rel: str, content: str = "") -> Path:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _resolve_relative_import
# ---------------------------------------------------------------------------


class TestResolveRelativeImport:
    """Tests for _resolve_relative_import internal helper."""

    def test_level_1_with_module(self) -> None:
        """from .util import x  in pkg.sub → pkg.sub.util"""
        assert _resolve_relative_import("util", 1, "pkg.sub") == "pkg.sub.util"

    def test_level_1_without_module(self) -> None:
        """from . import x  in pkg.sub → pkg.sub"""
        assert _resolve_relative_import(None, 1, "pkg.sub") == "pkg.sub"

    def test_level_2_with_module(self) -> None:
        """from ..sibling import x  in pkg.sub → pkg.sibling"""
        assert _resolve_relative_import("sibling", 2, "pkg.sub") == "pkg.sibling"

    def test_level_2_without_module(self) -> None:
        """from .. import x  in pkg.sub → pkg"""
        assert _resolve_relative_import(None, 2, "pkg.sub") == "pkg"

    def test_level_exceeds_package_depth_returns_none(self) -> None:
        """Relative import deeper than the package hierarchy returns None."""
        # pkg has depth 1; level 3 needs ancestor_depth=2 > 1 → None
        assert _resolve_relative_import("foo", 3, "pkg") is None

    def test_level_1_top_level_package(self) -> None:
        """from .mod import x  in a top-level package stays in that package."""
        assert _resolve_relative_import("mod", 1, "pkg") == "pkg.mod"

    def test_empty_current_package_level_1_no_module(self) -> None:
        """from . import x  at the top level (empty package) → None (empty string)."""
        result = _resolve_relative_import(None, 1, "")
        # Empty package + level 1 + no module → empty string → None-like
        assert result is None or result == ""

    def test_deeply_nested_level_2(self) -> None:
        """from .. import x  in a.b.c → a.b"""
        assert _resolve_relative_import(None, 2, "a.b.c") == "a.b"

    def test_deeply_nested_level_3_with_module(self) -> None:
        """from ...utils import x  in a.b.c → a.utils"""
        assert _resolve_relative_import("utils", 3, "a.b.c") == "a.utils"


# ---------------------------------------------------------------------------
# ImportExtractor
# ---------------------------------------------------------------------------


class TestImportExtractor:
    """Tests for the ImportExtractor AST visitor."""

    def test_visit_import(self) -> None:
        """import os; import sys → both recorded."""
        import ast

        tree = ast.parse("import os\nimport sys\n")
        extractor = ImportExtractor("pkg")
        extractor.visit(tree)
        assert "os" in extractor.imported_modules
        assert "sys" in extractor.imported_modules

    def test_visit_import_dotted(self) -> None:
        """import os.path → recorded as 'os.path'."""
        import ast

        tree = ast.parse("import os.path\n")
        extractor = ImportExtractor("")
        extractor.visit(tree)
        assert "os.path" in extractor.imported_modules

    def test_visit_import_from_absolute(self) -> None:
        """from pathlib import Path → records 'pathlib'."""
        import ast

        tree = ast.parse("from pathlib import Path\n")
        extractor = ImportExtractor("")
        extractor.visit(tree)
        assert "pathlib" in extractor.imported_modules

    def test_visit_import_from_relative(self) -> None:
        """from .core import x  in 'sample' → records 'sample.core'."""
        import ast

        tree = ast.parse("from .core import compute\n")
        extractor = ImportExtractor("sample")
        extractor.visit(tree)
        assert "sample.core" in extractor.imported_modules

    def test_visit_import_from_relative_no_module(self) -> None:
        """from . import sibling  in 'pkg.sub' → records 'pkg.sub'."""
        import ast

        tree = ast.parse("from . import sibling\n")
        extractor = ImportExtractor("pkg.sub")
        extractor.visit(tree)
        assert "pkg.sub" in extractor.imported_modules

    def test_skips_unresolvable_relative(self) -> None:
        """Relative import too deep for the package depth does not add None."""
        import ast

        tree = ast.parse("from .... import x\n")
        extractor = ImportExtractor("pkg")
        extractor.visit(tree)
        assert None not in extractor.imported_modules


# ---------------------------------------------------------------------------
# extract_imports
# ---------------------------------------------------------------------------


class TestExtractImports:
    """Tests for extract_imports()."""

    def test_absolute_imports(self, tmp_path: Path) -> None:
        src = write_py(
            tmp_path,
            "mod.py",
            """\
            import os
            import sys
            from pathlib import Path
            """,
        )
        imports = extract_imports(src, "")
        assert "os" in imports
        assert "sys" in imports
        assert "pathlib" in imports

    def test_relative_imports_resolved(self, tmp_path: Path) -> None:
        src = write_py(
            tmp_path,
            "pkg/sub/mod.py",
            """\
            from . import sibling
            from .. import parent_mod
            from .util import helper
            """,
        )
        imports = extract_imports(src, "pkg.sub")
        assert "pkg.sub" in imports
        assert "pkg" in imports
        assert "pkg.sub.util" in imports

    def test_syntax_error_returns_empty(self, tmp_path: Path) -> None:
        src = write_py(tmp_path, "bad.py", "def (")
        assert extract_imports(src, "") == []

    def test_deduplicates_repeated_imports(self, tmp_path: Path) -> None:
        src = write_py(
            tmp_path,
            "mod.py",
            """\
            import os
            import os
            """,
        )
        imports = extract_imports(src, "")
        assert imports.count("os") == 1

    def test_preserves_order_of_first_occurrence(self, tmp_path: Path) -> None:
        src = write_py(
            tmp_path,
            "mod.py",
            """\
            import sys
            import os
            import pathlib
            """,
        )
        imports = extract_imports(src, "")
        assert imports.index("sys") < imports.index("os") < imports.index("pathlib")

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        src = write_py(tmp_path, "empty.py", "")
        assert extract_imports(src, "") == []

    def test_no_import_statements_returns_empty(self, tmp_path: Path) -> None:
        src = write_py(tmp_path, "no_imports.py", "x = 1\ny = 2\n")
        assert extract_imports(src, "") == []


# ---------------------------------------------------------------------------
# find_python_files
# ---------------------------------------------------------------------------


class TestFindPythonFiles:
    """Tests for find_python_files()."""

    def test_finds_basic_py_files(self, tmp_path: Path) -> None:
        write_py(tmp_path, "pkg/__init__.py")
        write_py(tmp_path, "pkg/mod.py")
        files = find_python_files(tmp_path)
        names = [f.name for f in files]
        assert "__init__.py" in names
        assert "mod.py" in names

    def test_excludes_pycache(self, tmp_path: Path) -> None:
        write_py(tmp_path, "pkg/__init__.py")
        write_py(tmp_path, "__pycache__/cached.cpython-311.py")
        files = find_python_files(tmp_path)
        assert not any("__pycache__" in str(f) for f in files)

    def test_excludes_venv(self, tmp_path: Path) -> None:
        write_py(tmp_path, "pkg/__init__.py")
        write_py(tmp_path, ".venv/lib/site.py")
        files = find_python_files(tmp_path)
        assert not any(".venv" in str(f) for f in files)

    def test_excludes_node_modules(self, tmp_path: Path) -> None:
        write_py(tmp_path, "src/pkg/__init__.py")
        write_py(tmp_path, "node_modules/helper.py")
        files = find_python_files(tmp_path)
        # Check path components, not the string repr (tmp_path name may contain substrings)
        assert not any("node_modules" in f.parts for f in files)

    def test_returns_empty_for_empty_dir(self, tmp_path: Path) -> None:
        assert find_python_files(tmp_path) == []

    def test_results_are_sorted(self, tmp_path: Path) -> None:
        write_py(tmp_path, "b.py")
        write_py(tmp_path, "a.py")
        files = find_python_files(tmp_path)
        assert files == sorted(files)

    def test_results_are_path_objects(self, tmp_path: Path) -> None:
        write_py(tmp_path, "mod.py")
        files = find_python_files(tmp_path)
        assert all(isinstance(f, Path) for f in files)


# ---------------------------------------------------------------------------
# extract_imports — fixture repo
# ---------------------------------------------------------------------------


class TestExtractImportsFixtureRepo:
    """Tests for extract_imports on files from the sample_repo fixture."""

    def test_core_imports_os_and_sys(self) -> None:
        core = FIXTURE_REPO / "src" / "sample" / "core.py"
        imports = extract_imports(core, "sample")
        assert "os" in imports
        assert "sys" in imports

    def test_main_imports_core(self) -> None:
        """__main__.py uses a relative import which resolves to sample.core."""
        main = FIXTURE_REPO / "src" / "sample" / "__main__.py"
        imports = extract_imports(main, "sample")
        assert "sample.core" in imports

    def test_init_has_no_imports(self) -> None:
        init = FIXTURE_REPO / "src" / "sample" / "__init__.py"
        imports = extract_imports(init, "sample")
        assert imports == []


# ---------------------------------------------------------------------------
# find_python_files — fixture repo
# ---------------------------------------------------------------------------


class TestFindPythonFilesFixtureRepo:
    """Tests for find_python_files on the sample_repo fixture."""

    def test_finds_all_three_py_files(self) -> None:
        files = find_python_files(FIXTURE_REPO)
        names = [f.name for f in files]
        assert "__init__.py" in names
        assert "__main__.py" in names
        assert "core.py" in names

    def test_finds_exactly_three_files(self) -> None:
        """The fixture has exactly three .py files."""
        files = find_python_files(FIXTURE_REPO)
        assert len(files) == 3
