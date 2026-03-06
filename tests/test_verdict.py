"""Tests for repo_audit.verdict scoring module.

Covers severity, staleness class, and confidence scoring for representative
GapSignal inputs, plus the full score_signal() and verdict() public APIs.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub 'beads' before any repo_audit import.
# ---------------------------------------------------------------------------
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

import pytest

from repo_audit.comparator.gap_signal import GapSignal
from repo_audit.verdict import verdict
from repo_audit.verdict.finding_bead import FindingBead
from repo_audit.verdict.scorer import (
    _confidence_for,
    _reasoning_for,
    _severity_for,
    _signal_id,
    _staleness_for,
    _summary_for,
    score_signal,
)


# ---------------------------------------------------------------------------
# _severity_for
# ---------------------------------------------------------------------------


class TestSeverityFor:
    """Tests for _severity_for heuristic."""

    def test_undocumented_module_is_low(self) -> None:
        sig = GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="mod")
        assert _severity_for(sig) == "low"

    def test_unreachable_module_is_medium(self) -> None:
        sig = GapSignal(layer="structural_vs_behavioral", kind="unreachable_module", subject="mod")
        assert _severity_for(sig) == "medium"

    def test_broken_entry_point_is_critical(self) -> None:
        sig = GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="ep")
        assert _severity_for(sig) == "critical"

    def test_untested_goal_is_high(self) -> None:
        sig = GapSignal(layer="test_vs_declared", kind="untested_goal", subject="goal")
        assert _severity_for(sig) == "high"

    def test_kind_overrides_layer_upward(self) -> None:
        """broken_entry_point in an unexpected layer still scores as critical."""
        sig = GapSignal(layer="declared_vs_structural", kind="broken_entry_point", subject="ep")
        assert _severity_for(sig) == "critical"

    def test_unknown_kind_falls_back_to_layer_severity(self) -> None:
        """An unrecognised kind falls back to the layer's default severity."""
        sig = GapSignal(layer="structural_vs_behavioral", kind="unknown_kind", subject="x")
        # structural_vs_behavioral default = medium
        assert _severity_for(sig) == "medium"

    def test_unknown_layer_and_kind_defaults_to_medium(self) -> None:
        """Completely unknown layer+kind defaults to medium (the fallback rank)."""
        sig = GapSignal(layer="unknown_layer", kind="unknown_kind", subject="x")
        assert _severity_for(sig) == "medium"

    def test_severity_rank_ordering(self) -> None:
        """Kind-level override must never lower the result below layer default."""
        # declared_vs_structural is 'low'; broken_entry_point is 'critical'.
        # The result is the higher of the two.
        sig = GapSignal(layer="declared_vs_structural", kind="broken_entry_point", subject="ep")
        assert _severity_for(sig) == "critical"


# ---------------------------------------------------------------------------
# _staleness_for
# ---------------------------------------------------------------------------


class TestStalenessFor:
    """Tests for _staleness_for heuristic."""

    def test_undocumented_module_is_architectural(self) -> None:
        sig = GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="mod")
        assert _staleness_for(sig) == "architectural"

    def test_unreachable_module_is_structural(self) -> None:
        sig = GapSignal(layer="structural_vs_behavioral", kind="unreachable_module", subject="mod")
        assert _staleness_for(sig) == "structural"

    def test_broken_entry_point_is_critical_staleness(self) -> None:
        sig = GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="ep")
        assert _staleness_for(sig) == "critical"

    def test_untested_goal_is_dependency(self) -> None:
        sig = GapSignal(layer="test_vs_declared", kind="untested_goal", subject="goal")
        assert _staleness_for(sig) == "dependency"

    def test_kind_takes_priority_over_layer(self) -> None:
        """broken_entry_point kind overrides any layer staleness class."""
        sig = GapSignal(layer="declared_vs_structural", kind="broken_entry_point", subject="ep")
        assert _staleness_for(sig) == "critical"

    def test_unknown_kind_falls_back_to_layer_staleness(self) -> None:
        """Unrecognised kind falls back to layer's default staleness class."""
        sig = GapSignal(layer="test_vs_declared", kind="unknown_kind", subject="x")
        assert _staleness_for(sig) == "dependency"

    def test_unknown_layer_and_kind_defaults_to_structural(self) -> None:
        """Completely unknown layer+kind defaults to structural."""
        sig = GapSignal(layer="unknown_layer", kind="unknown_kind", subject="x")
        assert _staleness_for(sig) == "structural"


# ---------------------------------------------------------------------------
# _confidence_for
# ---------------------------------------------------------------------------


class TestConfidenceFor:
    """Tests for _confidence_for heuristic."""

    def test_zero_evidence_gives_zero_confidence(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=[])
        assert _confidence_for(sig) == 0.0

    def test_one_evidence_gives_0_2(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e1"])
        assert _confidence_for(sig) == pytest.approx(0.2)

    def test_two_evidence_gives_0_4(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e1", "e2"])
        assert _confidence_for(sig) == pytest.approx(0.4)

    def test_three_evidence_gives_0_6(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e1", "e2", "e3"])
        assert _confidence_for(sig) == pytest.approx(0.6)

    def test_five_evidence_is_capped_at_0_95(self) -> None:
        """Five pieces of evidence would be 1.0 but the cap is 0.95."""
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e"] * 5)
        assert _confidence_for(sig) == pytest.approx(0.95)

    def test_many_evidence_capped_at_0_95(self) -> None:
        """The cap holds regardless of how many evidence items there are."""
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e"] * 100)
        assert _confidence_for(sig) == pytest.approx(0.95)

    def test_confidence_never_exceeds_0_95(self) -> None:
        for n in range(1, 20):
            sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e"] * n)
            assert _confidence_for(sig) <= 0.95


# ---------------------------------------------------------------------------
# _signal_id
# ---------------------------------------------------------------------------


class TestSignalId:
    """Tests for _signal_id determinism and format."""

    def test_same_inputs_produce_same_id(self) -> None:
        sig1 = GapSignal(layer="l", kind="k", subject="s")
        sig2 = GapSignal(layer="l", kind="k", subject="s")
        assert _signal_id(sig1) == _signal_id(sig2)

    def test_different_subject_produces_different_id(self) -> None:
        sig1 = GapSignal(layer="l", kind="k", subject="s1")
        sig2 = GapSignal(layer="l", kind="k", subject="s2")
        assert _signal_id(sig1) != _signal_id(sig2)

    def test_different_kind_produces_different_id(self) -> None:
        sig1 = GapSignal(layer="l", kind="k1", subject="s")
        sig2 = GapSignal(layer="l", kind="k2", subject="s")
        assert _signal_id(sig1) != _signal_id(sig2)

    def test_id_is_16_characters(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        assert len(_signal_id(sig)) == 16

    def test_id_is_hex_lowercase(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        assert all(c in "0123456789abcdef" for c in _signal_id(sig))


# ---------------------------------------------------------------------------
# _summary_for
# ---------------------------------------------------------------------------


class TestSummaryFor:
    """Tests for _summary_for formatting."""

    def test_undocumented_module_summary(self) -> None:
        sig = GapSignal(layer="l", kind="undocumented_module", subject="my.module")
        assert _summary_for(sig) == "Undocumented Module: my.module"

    def test_unreachable_module_summary(self) -> None:
        sig = GapSignal(layer="l", kind="unreachable_module", subject="pkg.dead")
        assert _summary_for(sig) == "Unreachable Module: pkg.dead"

    def test_broken_entry_point_summary(self) -> None:
        sig = GapSignal(layer="l", kind="broken_entry_point", subject="cli")
        assert _summary_for(sig) == "Broken Entry Point: cli"

    def test_untested_goal_summary(self) -> None:
        sig = GapSignal(layer="l", kind="untested_goal", subject="Do the thing")
        assert _summary_for(sig) == "Untested Goal: Do the thing"


# ---------------------------------------------------------------------------
# _reasoning_for
# ---------------------------------------------------------------------------


class TestReasoningFor:
    """Tests for _reasoning_for content."""

    def test_reasoning_mentions_subject(self) -> None:
        sig = GapSignal(
            layer="declared_vs_structural",
            kind="undocumented_module",
            subject="my.module",
        )
        assert "my.module" in _reasoning_for(sig)

    def test_reasoning_includes_evidence(self) -> None:
        sig = GapSignal(
            layer="l",
            kind="k",
            subject="s",
            evidence=["Evidence A", "Evidence B"],
        )
        reasoning = _reasoning_for(sig)
        assert "Evidence A" in reasoning
        assert "Evidence B" in reasoning

    def test_reasoning_with_no_evidence_does_not_crash(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=[])
        reasoning = _reasoning_for(sig)
        assert isinstance(reasoning, str)
        assert len(reasoning) > 0


# ---------------------------------------------------------------------------
# score_signal
# ---------------------------------------------------------------------------


class TestScoreSignal:
    """Tests for score_signal() output fields."""

    def test_returns_finding_bead(self) -> None:
        sig = GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="mod")
        bead = score_signal(sig)
        assert isinstance(bead, FindingBead)

    def test_severity_is_propagated(self) -> None:
        sig = GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="ep")
        bead = score_signal(sig)
        assert bead.severity == "critical"

    def test_staleness_class_is_propagated(self) -> None:
        sig = GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="ep")
        bead = score_signal(sig)
        assert bead.staleness_class == "critical"

    def test_confidence_derived_from_evidence_count(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=["e1", "e2"])
        bead = score_signal(sig)
        assert bead.confidence == pytest.approx(0.4)

    def test_evidence_chain_matches_signal_evidence(self) -> None:
        evidence = ["Evidence A", "Evidence B"]
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=evidence)
        bead = score_signal(sig)
        assert bead.evidence_chain == evidence

    def test_evidence_chain_is_a_copy(self) -> None:
        """Mutating the original signal's evidence does not affect the bead."""
        evidence = ["e1"]
        sig = GapSignal(layer="l", kind="k", subject="s", evidence=evidence)
        bead = score_signal(sig)
        evidence.append("e2")
        assert bead.evidence_chain == ["e1"]

    def test_cycle_id_is_passed_through(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead = score_signal(sig, cycle_id="20240101T120000Z")
        assert bead.cycle_id == "20240101T120000Z"

    def test_repo_path_is_passed_through(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead = score_signal(sig, repo_path="/some/path")
        assert bead.repo_path == "/some/path"

    def test_default_agent_is_repo_audit(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead = score_signal(sig)
        assert bead.agent == "repo-audit"

    def test_custom_agent_is_passed_through(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead = score_signal(sig, agent="custom-agent")
        assert bead.agent == "custom-agent"

    def test_id_is_deterministic(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead1 = score_signal(sig)
        bead2 = score_signal(sig)
        assert bead1.id == bead2.id

    def test_id_is_16_chars(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        bead = score_signal(sig)
        assert len(bead.id) == 16

    def test_summary_contains_subject(self) -> None:
        sig = GapSignal(layer="l", kind="undocumented_module", subject="my.module")
        bead = score_signal(sig)
        assert "my.module" in bead.summary

    def test_reasoning_contains_subject(self) -> None:
        sig = GapSignal(
            layer="declared_vs_structural",
            kind="undocumented_module",
            subject="my.module",
        )
        bead = score_signal(sig)
        assert "my.module" in bead.reasoning

    # Representative signals for each gap kind.

    def test_undocumented_module_full_scoring(self) -> None:
        sig = GapSignal(
            layer="declared_vs_structural",
            kind="undocumented_module",
            subject="pkg.mod",
            evidence=["pkg/mod.py exists but has no docstring"],
        )
        bead = score_signal(sig, cycle_id="c1", repo_path="/repo")
        assert bead.severity == "low"
        assert bead.staleness_class == "architectural"
        assert bead.confidence == pytest.approx(0.2)
        assert bead.cycle_id == "c1"
        assert bead.repo_path == "/repo"

    def test_unreachable_module_full_scoring(self) -> None:
        sig = GapSignal(
            layer="structural_vs_behavioral",
            kind="unreachable_module",
            subject="pkg.orphan",
            evidence=["Not reachable from any entry point"],
        )
        bead = score_signal(sig)
        assert bead.severity == "medium"
        assert bead.staleness_class == "structural"

    def test_broken_entry_point_full_scoring(self) -> None:
        sig = GapSignal(
            layer="behavioral_vs_activated",
            kind="broken_entry_point",
            subject="cli-tool",
            evidence=["Targets 'pkg.missing:run'", "Module 'pkg.missing' not in graph"],
        )
        bead = score_signal(sig)
        assert bead.severity == "critical"
        assert bead.staleness_class == "critical"
        assert bead.confidence == pytest.approx(0.4)

    def test_untested_goal_full_scoring(self) -> None:
        sig = GapSignal(
            layer="test_vs_declared",
            kind="untested_goal",
            subject="The core module should be tested",
            evidence=["Declared in specs/design.md", "No test coverage for pkg.core"],
        )
        bead = score_signal(sig)
        assert bead.severity == "high"
        assert bead.staleness_class == "dependency"
        assert bead.confidence == pytest.approx(0.4)


# ---------------------------------------------------------------------------
# verdict() top-level
# ---------------------------------------------------------------------------


class TestVerdict:
    """Tests for the verdict() top-level function."""

    def test_empty_signals_returns_empty_list(self) -> None:
        assert verdict([]) == []

    def test_one_signal_returns_one_bead(self) -> None:
        sig = GapSignal(layer="l", kind="k", subject="s")
        beads = verdict([sig])
        assert len(beads) == 1
        assert isinstance(beads[0], FindingBead)

    def test_output_length_matches_input_length(self) -> None:
        sigs = [GapSignal(layer="l", kind="k", subject=f"s{i}") for i in range(5)]
        beads = verdict(sigs)
        assert len(beads) == 5

    def test_output_order_mirrors_input_order(self) -> None:
        """Beads appear in the same order as the input signals."""
        sigs = [
            GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="mod_a"),
            GapSignal(
                layer="structural_vs_behavioral", kind="unreachable_module", subject="mod_b"
            ),
        ]
        beads = verdict(sigs)
        assert "mod_a" in beads[0].summary
        assert "mod_b" in beads[1].summary

    def test_cycle_id_propagated_to_all_beads(self) -> None:
        sigs = [GapSignal(layer="l", kind="k", subject=f"s{i}") for i in range(3)]
        beads = verdict(sigs, cycle_id="20240101T120000Z")
        assert all(b.cycle_id == "20240101T120000Z" for b in beads)

    def test_repo_path_propagated_to_all_beads(self) -> None:
        sigs = [GapSignal(layer="l", kind="k", subject="s")]
        beads = verdict(sigs, repo_path="/some/repo")
        assert beads[0].repo_path == "/some/repo"

    def test_agent_propagated_to_all_beads(self) -> None:
        sigs = [GapSignal(layer="l", kind="k", subject="s")]
        beads = verdict(sigs, agent="custom-agent")
        assert beads[0].agent == "custom-agent"

    def test_each_bead_has_valid_severity(self) -> None:
        valid = {"low", "medium", "high", "critical"}
        sigs = [
            GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="m"),
            GapSignal(layer="structural_vs_behavioral", kind="unreachable_module", subject="m"),
            GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="m"),
            GapSignal(layer="test_vs_declared", kind="untested_goal", subject="m"),
        ]
        for bead in verdict(sigs):
            assert bead.severity in valid

    def test_each_bead_has_valid_staleness_class(self) -> None:
        valid = {"critical", "dependency", "structural", "architectural"}
        sigs = [
            GapSignal(layer="declared_vs_structural", kind="undocumented_module", subject="m"),
            GapSignal(layer="structural_vs_behavioral", kind="unreachable_module", subject="m"),
            GapSignal(layer="behavioral_vs_activated", kind="broken_entry_point", subject="m"),
            GapSignal(layer="test_vs_declared", kind="untested_goal", subject="m"),
        ]
        for bead in verdict(sigs):
            assert bead.staleness_class in valid
