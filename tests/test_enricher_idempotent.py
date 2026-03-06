"""Tests for Enricher idempotency — skip already-enriched findings.

The Enricher is idempotent by design: it only processes findings where
``reasoning_extended is None``.  Findings that already have a value are
skipped unconditionally.  The ``--re-enrich`` CLI flag (tested separately in
test_cli_enrich_flags.py) clears those fields before calling the enricher so
that they appear unenriched again.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

# Stub 'beads' before any repo_audit import.
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from repo_audit.enricher.enricher import Enricher  # noqa: E402
from repo_audit.verdict.finding_bead import FindingBead  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str,
    reasoning_extended: str | None = None,
    remediation_sketch: str | None = None,
) -> FindingBead:
    return FindingBead(
        id=id,
        agent="test-agent",
        severity="high",
        staleness_class="critical",
        confidence=0.9,
        evidence_chain=["e1"],
        reasoning="some reasoning",
        cycle_id="20240101T000000Z",
        repo_path="/tmp/repo",
        summary=f"Finding {id}",
        reasoning_extended=reasoning_extended,
        remediation_sketch=remediation_sketch,
    )


def _good_response(text: str = "analysis", sketch: str = "fix") -> MagicMock:
    resp = MagicMock()
    resp.content[0].text = json.dumps({"reasoning_extended": text, "remediation_sketch": sketch})
    resp.usage.input_tokens = 50
    resp.usage.output_tokens = 20
    return resp


# ---------------------------------------------------------------------------
# Idempotency: skip already-enriched findings
# ---------------------------------------------------------------------------


class TestEnricherSkipsAlreadyEnriched:
    """Enricher must skip findings where reasoning_extended is not None."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        return MagicMock()

    def test_fully_enriched_finding_is_skipped(self, mock_store: MagicMock) -> None:
        """A finding with reasoning_extended already set is not re-enriched."""
        mock_store.list_findings.return_value = [
            _make_finding("f1", reasoning_extended="existing analysis")
        ]
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 0
        mock_store.patch_finding.assert_not_called()

    def test_finding_with_empty_string_reasoning_is_skipped(self, mock_store: MagicMock) -> None:
        """reasoning_extended='' is not None — the finding is treated as enriched."""
        mock_store.list_findings.return_value = [_make_finding("f1", reasoning_extended="")]
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 0

    def test_finding_with_none_reasoning_is_processed(self, mock_store: MagicMock) -> None:
        """A finding with reasoning_extended=None is selected for enrichment."""
        mock_store.list_findings.return_value = [_make_finding("f1", reasoning_extended=None)]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 1
        mock_store.patch_finding.assert_called_once()

    def test_all_enriched_returns_zero_regardless_of_count(self, mock_store: MagicMock) -> None:
        """When every finding is already enriched, count is always 0."""
        mock_store.list_findings.return_value = [
            _make_finding(f"f{i}", reasoning_extended=f"analysis {i}") for i in range(10)
        ]
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 0


# ---------------------------------------------------------------------------
# Idempotency: mixed — some enriched, some not
# ---------------------------------------------------------------------------


class TestEnricherMixedFindings:
    """Enricher processes only the unenriched subset when findings are mixed."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        return MagicMock()

    def test_only_unenriched_findings_are_patched(self, mock_store: MagicMock) -> None:
        """patch_finding is called only for findings with reasoning_extended=None."""
        mock_store.list_findings.return_value = [
            _make_finding("already", reasoning_extended="done"),
            _make_finding("needs-enrichment", reasoning_extended=None),
            _make_finding("also-done", reasoning_extended="also done"),
        ]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response()
            count = Enricher(store=mock_store).enrich("owner/repo")

        assert count == 1
        # Only the unenriched finding should be patched.
        mock_store.patch_finding.assert_called_once()
        call_args = mock_store.patch_finding.call_args
        assert call_args.args[1] == "needs-enrichment"

    def test_count_reflects_only_newly_enriched(self, mock_store: MagicMock) -> None:
        """Return value counts only the findings enriched in this call."""
        mock_store.list_findings.return_value = [
            _make_finding("e1", reasoning_extended="old"),
            _make_finding("e2", reasoning_extended="old"),
            _make_finding("n1", reasoning_extended=None),
            _make_finding("n2", reasoning_extended=None),
        ]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 2

    def test_enriched_finding_ids_are_correct(self, mock_store: MagicMock) -> None:
        """patch_finding is called with the correct finding ids."""
        mock_store.list_findings.return_value = [
            _make_finding("skip-me", reasoning_extended="present"),
            _make_finding("enrich-me", reasoning_extended=None),
        ]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response()
            Enricher(store=mock_store).enrich("owner/repo")

        patched_ids = [call.args[1] for call in mock_store.patch_finding.call_args_list]
        assert "enrich-me" in patched_ids
        assert "skip-me" not in patched_ids

    def test_api_call_count_matches_unenriched_count(self, mock_store: MagicMock) -> None:
        """messages.create is called once per unenriched finding, not per total finding."""
        mock_store.list_findings.return_value = [
            _make_finding("done", reasoning_extended="yes"),
            _make_finding("todo-a", reasoning_extended=None),
            _make_finding("todo-b", reasoning_extended=None),
        ]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response()
            Enricher(store=mock_store).enrich("owner/repo")
        assert mock_client.messages.create.call_count == 2


# ---------------------------------------------------------------------------
# Re-enrichment: once reasoning_extended is cleared, Enricher will process again
# ---------------------------------------------------------------------------


class TestReEnrichmentAfterClear:
    """Simulate the --re-enrich path: fields cleared → Enricher processes again."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        return MagicMock()

    def test_cleared_finding_is_re_enriched(self, mock_store: MagicMock) -> None:
        """A finding whose reasoning_extended was reset to None is processed."""
        # Simulate post-clear state: the CLI sets reasoning_extended=None before
        # calling enrich().  From the Enricher's perspective it is a fresh finding.
        mock_store.list_findings.return_value = [
            _make_finding("previously-enriched", reasoning_extended=None)
        ]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _good_response("new analysis", "new fix")
            count = Enricher(store=mock_store).enrich("owner/repo")

        assert count == 1
        mock_store.patch_finding.assert_called_once_with(
            "owner/repo",
            "previously-enriched",
            reasoning_extended="new analysis",
            remediation_sketch="new fix",
            enrichment_cost_usd=pytest.approx(50 * 8e-7 + 20 * 4e-6),
        )

    def test_second_call_with_no_unenriched_is_noop(self, mock_store: MagicMock) -> None:
        """Calling enrich() when all findings are enriched is a no-op (idempotent)."""
        mock_store.list_findings.return_value = [
            _make_finding("f1", reasoning_extended="analysis")
        ]
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            count1 = Enricher(store=mock_store).enrich("owner/repo")
            count2 = Enricher(store=mock_store).enrich("owner/repo")
        assert count1 == 0
        assert count2 == 0
        mock_store.patch_finding.assert_not_called()
