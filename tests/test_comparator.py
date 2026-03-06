"""Tests for repo_audit.comparator layer functions.

Covers all four layer functions using synthetic AnalysisResult / CollectedArtifacts
stubs plus the tests/fixtures/sample_repo fixture for end-to-end smoke tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub 'beads' before any repo_audit import.
# repo_audit/__init__.py imports from store.bead_store which imports beads.
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from repo_audit.analyzer.result import AnalysisResult
from repo_audit.collector.artifacts import CollectedArtifacts
from repo_audit.comparator import compare
from repo_audit.comparator.gap_signal import GapSignal
from repo_audit.comparator.layers import (
    LAYER_BEHAVIORAL_VS_ACTIVATED,
    LAYER_DECLARED_VS_STRUCTURAL,
    LAYER_STRUCTURAL_VS_BEHAVIORAL,
    LAYER_TEST_VS_DECLARED,
    behavioral_vs_activated,
    declared_vs_structural,
    structural_vs_behavioral,
    test_vs_declared as _test_vs_declared,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"


# ---------------------------------------------------------------------------
# Layer 1: declared_vs_structural
# ---------------------------------------------------------------------------


class TestDeclaredVsStructural:
    """Tests for declared_vs_structural."""

    def test_module_with_docstring_returns_no_signal(self) -> None:
        """A module with a non-None docstring is not flagged."""
        artifacts = CollectedArtifacts(docstrings={"mymod/utils.py": "A utility module."})
        analysis = AnalysisResult(import_graph={"mymod.utils": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert signals == []

    def test_module_with_none_docstring_returns_signal(self) -> None:
        """A module whose docstring is None is flagged as undocumented."""
        artifacts = CollectedArtifacts(docstrings={"mymod/utils.py": None})
        analysis = AnalysisResult(import_graph={"mymod.utils": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert len(signals) == 1
        sig = signals[0]
        assert sig.layer == LAYER_DECLARED_VS_STRUCTURAL
        assert sig.kind == "undocumented_module"
        assert sig.subject == "mymod.utils"

    def test_module_absent_from_docstrings_is_skipped(self) -> None:
        """Modules not in docstrings (external deps) are ignored."""
        artifacts = CollectedArtifacts(docstrings={})
        analysis = AnalysisResult(import_graph={"some.external.lib": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert signals == []

    def test_multiple_modules_only_undocumented_flagged(self) -> None:
        """Among several modules, only those with None docstrings are flagged."""
        artifacts = CollectedArtifacts(
            docstrings={
                "pkg/a.py": "Documented.",
                "pkg/b.py": None,
                "pkg/c.py": "Also documented.",
            }
        )
        analysis = AnalysisResult(import_graph={"pkg.a": [], "pkg.b": [], "pkg.c": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert len(signals) == 1
        assert signals[0].subject == "pkg.b"

    def test_package_init_path_matches_module(self) -> None:
        """The pkg/sub/__init__.py path convention matches module pkg.sub."""
        artifacts = CollectedArtifacts(docstrings={"pkg/submod/__init__.py": None})
        analysis = AnalysisResult(import_graph={"pkg.submod": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert len(signals) == 1
        assert signals[0].subject == "pkg.submod"

    def test_evidence_mentions_module_name(self) -> None:
        """Signal evidence references the undocumented module name."""
        artifacts = CollectedArtifacts(docstrings={"mymod/core.py": None})
        analysis = AnalysisResult(import_graph={"mymod.core": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert len(signals) == 1
        assert any("mymod.core" in e for e in signals[0].evidence)

    def test_empty_import_graph_returns_no_signals(self) -> None:
        """No modules in the graph produces no signals."""
        artifacts = CollectedArtifacts(docstrings={"pkg/a.py": None})
        analysis = AnalysisResult(import_graph={})
        signals = declared_vs_structural(artifacts, analysis)
        assert signals == []

    def test_returns_one_signal_per_undocumented_module(self) -> None:
        """Exactly one signal per undocumented module."""
        artifacts = CollectedArtifacts(
            docstrings={"pkg/x.py": None, "pkg/y.py": None, "pkg/z.py": "ok"}
        )
        analysis = AnalysisResult(import_graph={"pkg.x": [], "pkg.y": [], "pkg.z": []})
        signals = declared_vs_structural(artifacts, analysis)
        assert len(signals) == 2
        subjects = {s.subject for s in signals}
        assert subjects == {"pkg.x", "pkg.y"}

    def test_fixture_repo_all_signals_are_undocumented_kind(self) -> None:
        """Running against sample_repo: any signals emitted must be undocumented_module."""
        from repo_audit.analyzer import analyze
        from repo_audit.collector import harvest

        artifacts = harvest(FIXTURE_REPO)
        analysis = analyze(FIXTURE_REPO)
        signals = declared_vs_structural(artifacts, analysis)
        assert isinstance(signals, list)
        for sig in signals:
            assert sig.kind == "undocumented_module"
            assert sig.layer == LAYER_DECLARED_VS_STRUCTURAL


# ---------------------------------------------------------------------------
# Layer 2: structural_vs_behavioral
# ---------------------------------------------------------------------------


class TestStructuralVsBehavioral:
    """Tests for structural_vs_behavioral."""

    def test_reachable_module_returns_no_signal(self) -> None:
        """A module in both the graph and the reachable set is not flagged."""
        analysis = AnalysisResult(
            import_graph={"pkg.core": []},
            reachable_from_entry_points=["pkg.core"],
        )
        signals = structural_vs_behavioral(analysis)
        assert signals == []

    def test_unreachable_module_returns_signal(self) -> None:
        """A module in the graph but absent from reachable set is flagged."""
        analysis = AnalysisResult(
            import_graph={"pkg.core": [], "pkg.orphan": []},
            reachable_from_entry_points=["pkg.core"],
        )
        signals = structural_vs_behavioral(analysis)
        assert len(signals) == 1
        sig = signals[0]
        assert sig.layer == LAYER_STRUCTURAL_VS_BEHAVIORAL
        assert sig.kind == "unreachable_module"
        assert sig.subject == "pkg.orphan"

    def test_empty_graph_returns_no_signals(self) -> None:
        """An empty import graph produces no signals."""
        analysis = AnalysisResult(import_graph={}, reachable_from_entry_points=[])
        signals = structural_vs_behavioral(analysis)
        assert signals == []

    def test_all_unreachable_returns_one_signal_each(self) -> None:
        """Every unreachable module produces exactly one signal."""
        analysis = AnalysisResult(
            import_graph={"pkg.a": [], "pkg.b": [], "pkg.c": []},
            reachable_from_entry_points=[],
        )
        signals = structural_vs_behavioral(analysis)
        assert len(signals) == 3
        subjects = {s.subject for s in signals}
        assert subjects == {"pkg.a", "pkg.b", "pkg.c"}

    def test_evidence_mentions_module(self) -> None:
        """Signal evidence references the unreachable module name."""
        analysis = AnalysisResult(
            import_graph={"pkg.dead": []},
            reachable_from_entry_points=[],
        )
        signals = structural_vs_behavioral(analysis)
        assert len(signals) == 1
        assert any("pkg.dead" in e for e in signals[0].evidence)

    def test_reachable_set_superset_of_graph_returns_no_signals(self) -> None:
        """Reachable set may contain modules not in the graph without issues."""
        analysis = AnalysisResult(
            import_graph={"pkg.a": []},
            reachable_from_entry_points=["pkg.a", "os", "sys"],
        )
        signals = structural_vs_behavioral(analysis)
        assert signals == []

    def test_fixture_repo_entry_point_module_is_not_flagged(self) -> None:
        """sample_repo's entry point module (sample.__main__) is reachable."""
        from repo_audit.analyzer import analyze

        analysis = analyze(FIXTURE_REPO)
        signals = structural_vs_behavioral(analysis)
        unreachable_subjects = {s.subject for s in signals}
        assert "sample.__main__" not in unreachable_subjects


# ---------------------------------------------------------------------------
# Layer 3: behavioral_vs_activated
# ---------------------------------------------------------------------------


class TestBehavioralVsActivated:
    """Tests for behavioral_vs_activated."""

    def test_valid_entry_point_returns_no_signal(self) -> None:
        """Entry points whose module is present in the graph are not flagged."""
        artifacts = CollectedArtifacts(entry_points={"app": "pkg.main:run"})
        analysis = AnalysisResult(import_graph={"pkg.main": []})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert signals == []

    def test_missing_module_returns_signal(self) -> None:
        """Entry points targeting a missing module are flagged as broken."""
        artifacts = CollectedArtifacts(entry_points={"app": "pkg.missing:run"})
        analysis = AnalysisResult(import_graph={"pkg.other": []})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert len(signals) == 1
        sig = signals[0]
        assert sig.layer == LAYER_BEHAVIORAL_VS_ACTIVATED
        assert sig.kind == "broken_entry_point"
        assert sig.subject == "app"

    def test_no_entry_points_returns_no_signals(self) -> None:
        """An empty entry_points dict yields no signals."""
        artifacts = CollectedArtifacts(entry_points={})
        analysis = AnalysisResult(import_graph={"pkg.main": []})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert signals == []

    def test_empty_module_part_is_skipped(self) -> None:
        """Entry point with target ':callable' (empty module part) is skipped."""
        artifacts = CollectedArtifacts(entry_points={"app": ":run"})
        analysis = AnalysisResult(import_graph={})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert signals == []

    def test_multiple_entry_points_only_broken_flagged(self) -> None:
        """Among several entry points, only broken ones are flagged."""
        artifacts = CollectedArtifacts(
            entry_points={
                "good-app": "pkg.main:run",
                "bad-app": "pkg.missing:run",
            }
        )
        analysis = AnalysisResult(import_graph={"pkg.main": []})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert len(signals) == 1
        assert signals[0].subject == "bad-app"

    def test_evidence_contains_target_string(self) -> None:
        """Signal evidence includes the full target and the missing module name."""
        artifacts = CollectedArtifacts(entry_points={"cli": "pkg.cli:main"})
        analysis = AnalysisResult(import_graph={})
        signals = behavioral_vs_activated(artifacts, analysis)
        assert len(signals) == 1
        evidence_text = " ".join(signals[0].evidence)
        assert "pkg.cli:main" in evidence_text
        assert "pkg.cli" in evidence_text

    def test_fixture_repo_entry_point_is_not_flagged(self) -> None:
        """sample_repo's 'sample-run' entry point must not be broken."""
        from repo_audit.analyzer import analyze
        from repo_audit.collector import harvest

        artifacts = harvest(FIXTURE_REPO)
        analysis = analyze(FIXTURE_REPO)
        signals = behavioral_vs_activated(artifacts, analysis)
        broken = {s.subject for s in signals}
        assert "sample-run" not in broken


# ---------------------------------------------------------------------------
# Layer 4: test_vs_declared
# ---------------------------------------------------------------------------


class TestTestVsDeclared:
    """Tests for test_vs_declared."""

    def test_no_specs_or_docs_returns_no_signals(self) -> None:
        """With no spec/doc files there are no assertions to check."""
        artifacts = CollectedArtifacts(specs={}, docs={})
        analysis = AnalysisResult(import_graph={})
        signals = _test_vs_declared(artifacts, analysis)
        assert signals == []

    def test_spec_without_goals_section_returns_no_signals(self) -> None:
        """Specs with no Goals/Validation/Requirements headings produce no signals."""
        spec_content = "# Overview\n\nThis module does stuff.\n"
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        analysis = AnalysisResult(import_graph={})
        signals = _test_vs_declared(artifacts, analysis)
        assert signals == []

    def test_goal_with_no_test_modules_returns_signal(self) -> None:
        """A goal assertion with no test modules in the graph is flagged."""
        spec_content = "## Goals\n\n- The system should process requests\n"
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        analysis = AnalysisResult(import_graph={"pkg.core": []})
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1
        sig = signals[0]
        assert sig.layer == LAYER_TEST_VS_DECLARED
        assert sig.kind == "untested_goal"

    def test_goal_with_tested_referenced_module_returns_no_signal(self) -> None:
        """Goal referencing a module imported by a test module is satisfied."""
        spec_content = "## Goals\n\n- The `core` module should process data\n"
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        analysis = AnalysisResult(
            import_graph={
                "pkg.core": [],
                "tests.test_core": ["pkg.core"],
            }
        )
        signals = _test_vs_declared(artifacts, analysis)
        assert signals == []

    def test_goal_with_untested_referenced_module_returns_signal(self) -> None:
        """Goal referencing a module not imported by any test is flagged."""
        spec_content = "## Goals\n\n- The `core` module should be fast\n"
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        analysis = AnalysisResult(
            import_graph={
                "pkg.core": [],
                "tests.test_other": ["pkg.utils"],
            }
        )
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1
        assert signals[0].kind == "untested_goal"

    def test_requirements_heading_is_detected(self) -> None:
        """'Requirements' headings are scanned for assertions."""
        spec_content = "## Requirements\n\n- The system must be reliable\n"
        artifacts = CollectedArtifacts(specs={"specs/reqs.md": spec_content})
        analysis = AnalysisResult(import_graph={"pkg.core": []})
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1

    def test_validation_heading_is_detected(self) -> None:
        """'Validation' headings are scanned for assertions."""
        spec_content = "## Validation\n\n- All data must be validated\n"
        artifacts = CollectedArtifacts(specs={"specs/val.md": spec_content})
        analysis = AnalysisResult(import_graph={})
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1

    def test_docs_field_is_scanned(self) -> None:
        """Goal assertions in docs files are checked, not just specs."""
        doc_content = "## Goals\n\n- The API should be documented\n"
        artifacts = CollectedArtifacts(specs={}, docs={"docs/api.md": doc_content})
        analysis = AnalysisResult(import_graph={})
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1

    def test_generic_goal_satisfied_by_any_test_module(self) -> None:
        """A goal with no module reference is satisfied when any test module exists."""
        spec_content = "## Goals\n\n- The overall system should work correctly\n"
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        # "test_something" starts with "test", so it qualifies as a test module.
        analysis = AnalysisResult(import_graph={"tests.test_something": ["pkg.core"]})
        signals = _test_vs_declared(artifacts, analysis)
        assert signals == []

    def test_multiple_goals_each_evaluated_independently(self) -> None:
        """Each goal bullet is independently checked; partial coverage yields partial signals."""
        spec_content = (
            "## Goals\n\n"
            "- The `core` module should handle input\n"
            "- The `storage` module should persist data\n"
        )
        artifacts = CollectedArtifacts(specs={"specs/design.md": spec_content})
        # test_core imports core but not storage.
        analysis = AnalysisResult(
            import_graph={
                "pkg.core": [],
                "pkg.storage": [],
                "tests.test_core": ["pkg.core"],
            }
        )
        signals = _test_vs_declared(artifacts, analysis)
        # Only the storage goal is uncovered.
        assert len(signals) == 1
        assert "storage" in signals[0].subject

    def test_evidence_contains_source_path(self) -> None:
        """Signal evidence includes the spec file path where the goal was declared."""
        spec_content = "## Goals\n\n- The system should work\n"
        artifacts = CollectedArtifacts(specs={"specs/my_spec.md": spec_content})
        analysis = AnalysisResult(import_graph={})
        signals = _test_vs_declared(artifacts, analysis)
        assert len(signals) == 1
        evidence_text = " ".join(signals[0].evidence)
        assert "specs/my_spec.md" in evidence_text


# ---------------------------------------------------------------------------
# Top-level compare() function
# ---------------------------------------------------------------------------


class TestCompare:
    """Tests for the top-level compare() entry point."""

    def test_returns_list(self) -> None:
        artifacts = CollectedArtifacts()
        analysis = AnalysisResult()
        result = compare(artifacts, analysis)
        assert isinstance(result, list)

    def test_all_items_are_gap_signals(self) -> None:
        """Every item returned by compare() is a GapSignal."""
        artifacts = CollectedArtifacts(
            entry_points={"bad": "missing.mod:fn"},
            docstrings={"pkg/a.py": None},
        )
        analysis = AnalysisResult(
            import_graph={"pkg.a": [], "pkg.b": []},
            reachable_from_entry_points=["pkg.a"],
        )
        result = compare(artifacts, analysis)
        for item in result:
            assert isinstance(item, GapSignal)

    def test_layer_order_is_preserved(self) -> None:
        """Results appear in declared→structural→behavioral→activated→test order."""
        artifacts = CollectedArtifacts(
            docstrings={"pkg/a.py": None},
            entry_points={"bad": "missing.mod:fn"},
        )
        analysis = AnalysisResult(
            import_graph={"pkg.a": [], "pkg.b": []},
            reachable_from_entry_points=["pkg.a"],
        )
        result = compare(artifacts, analysis)
        layers_seen = [s.layer for s in result]
        # declared_vs_structural must appear before structural_vs_behavioral, etc.
        layer_order = [
            LAYER_DECLARED_VS_STRUCTURAL,
            LAYER_STRUCTURAL_VS_BEHAVIORAL,
            LAYER_BEHAVIORAL_VS_ACTIVATED,
            LAYER_TEST_VS_DECLARED,
        ]
        # Check that whenever a layer appears it respects the ordering.
        last_rank = -1
        for layer in layers_seen:
            if layer in layer_order:
                rank = layer_order.index(layer)
                assert rank >= last_rank
                last_rank = rank

    def test_empty_inputs_returns_empty_list(self) -> None:
        """No artifacts or modules → no signals."""
        artifacts = CollectedArtifacts()
        analysis = AnalysisResult()
        result = compare(artifacts, analysis)
        assert result == []
