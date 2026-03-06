"""Tests for repo_audit.enricher.enricher — Enricher, _parse_enrichment_response, _calculate_cost."""

from __future__ import annotations

import json
import sys
import warnings
from unittest.mock import MagicMock, patch

import pytest

# Stub 'beads' before any repo_audit import that might pull in the store.
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from repo_audit.enricher.enricher import (  # noqa: E402
    DEFAULT_MODEL,
    Enricher,
    _calculate_cost,
    _parse_enrichment_response,
)
from repo_audit.verdict.finding_bead import FindingBead  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "abc123",
    reasoning_extended: str | None = None,
) -> FindingBead:
    """Return a minimal FindingBead for use in tests."""
    return FindingBead(
        id=id,
        agent="test-agent",
        severity="medium",
        staleness_class="structural",
        confidence=0.8,
        evidence_chain=["evidence1"],
        reasoning="some reasoning",
        cycle_id="20240101T000000Z",
        repo_path="/tmp/repo",
        summary="Test finding",
        reasoning_extended=reasoning_extended,
    )


def _make_mock_response(
    reasoning_extended: str = "extended reasoning",
    remediation_sketch: str = "fix it",
    input_tokens: int = 100,
    output_tokens: int = 50,
) -> MagicMock:
    """Return a MagicMock shaped like an anthropic Messages response."""
    response = MagicMock()
    response.content[0].text = json.dumps(
        {
            "reasoning_extended": reasoning_extended,
            "remediation_sketch": remediation_sketch,
        }
    )
    response.usage.input_tokens = input_tokens
    response.usage.output_tokens = output_tokens
    return response


# ---------------------------------------------------------------------------
# Enricher.enrich — happy paths
# ---------------------------------------------------------------------------


class TestEnricherEnrichHappyPath:
    """Tests for Enricher.enrich() when the API is available and calls succeed."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        store = MagicMock()
        store.list_findings.return_value = []
        return store

    def test_returns_zero_when_no_findings(self, mock_store: MagicMock) -> None:
        """Returns 0 when store has no findings."""
        with patch("anthropic.Anthropic"):
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 0
        mock_store.patch_finding.assert_not_called()

    def test_enriches_single_finding_returns_one(self, mock_store: MagicMock) -> None:
        """Returns 1 after successfully enriching a single finding."""
        mock_store.list_findings.return_value = [_make_finding(id="f1")]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 1

    def test_patch_finding_called_with_correct_fields(self, mock_store: MagicMock) -> None:
        """patch_finding receives reasoning_extended, remediation_sketch, and enrichment_cost_usd."""
        mock_store.list_findings.return_value = [_make_finding(id="f1")]
        response = _make_mock_response(
            reasoning_extended="deep analysis",
            remediation_sketch="fix the code",
            input_tokens=100,
            output_tokens=50,
        )
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = response
            Enricher(store=mock_store).enrich("owner/repo")

        expected_cost = pytest.approx(100 * 8e-7 + 50 * 4e-6)
        mock_store.patch_finding.assert_called_once_with(
            "owner/repo",
            "f1",
            reasoning_extended="deep analysis",
            remediation_sketch="fix the code",
            enrichment_cost_usd=expected_cost,
        )

    def test_enriches_multiple_findings(self, mock_store: MagicMock) -> None:
        """Returns correct count when multiple findings are enriched."""
        mock_store.list_findings.return_value = [_make_finding(id=f"f{i}") for i in range(4)]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            count = Enricher(store=mock_store).enrich("owner/repo")

        assert count == 4
        assert mock_store.patch_finding.call_count == 4

    def test_each_finding_gets_its_own_api_call(self, mock_store: MagicMock) -> None:
        """messages.create is called once per finding."""
        findings = [_make_finding(id=f"f{i}") for i in range(3)]
        mock_store.list_findings.return_value = findings
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            Enricher(store=mock_store).enrich("owner/repo")
        assert mock_client.messages.create.call_count == 3


# ---------------------------------------------------------------------------
# Enricher.enrich — batching
# ---------------------------------------------------------------------------


class TestEnricherBatching:
    """Tests that batching divides findings correctly across batch iterations."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        store = MagicMock()
        return store

    def test_all_findings_enriched_with_exact_batch_multiple(self, mock_store: MagicMock) -> None:
        """15 findings with batch_size=5 → all 15 are enriched."""
        mock_store.list_findings.return_value = [_make_finding(id=f"f{i}") for i in range(15)]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            count = Enricher(store=mock_store, batch_size=5).enrich("owner/repo")
        assert count == 15
        assert mock_store.patch_finding.call_count == 15

    def test_all_findings_enriched_with_partial_last_batch(self, mock_store: MagicMock) -> None:
        """7 findings with batch_size=3 → 3+3+1, all 7 enriched."""
        mock_store.list_findings.return_value = [_make_finding(id=f"f{i}") for i in range(7)]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            count = Enricher(store=mock_store, batch_size=3).enrich("owner/repo")
        assert count == 7

    def test_single_batch_when_fewer_than_batch_size(self, mock_store: MagicMock) -> None:
        """2 findings with batch_size=10 → single batch, both enriched."""
        mock_store.list_findings.return_value = [_make_finding(id=f"f{i}") for i in range(2)]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            count = Enricher(store=mock_store, batch_size=10).enrich("owner/repo")
        assert count == 2


# ---------------------------------------------------------------------------
# Enricher.enrich — error handling
# ---------------------------------------------------------------------------


class TestEnricherErrorHandling:
    """Tests for Enricher.enrich() error and edge-case paths."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        store = MagicMock()
        return store

    def test_api_failure_emits_warning(self, mock_store: MagicMock) -> None:
        """An API error for a finding emits a UserWarning mentioning the finding id."""
        mock_store.list_findings.return_value = [_make_finding(id="bad-finding")]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.side_effect = RuntimeError("network error")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                Enricher(store=mock_store).enrich("owner/repo")
        assert any("bad-finding" in str(w.message) for w in caught)

    def test_api_failure_processing_continues_for_other_findings(
        self, mock_store: MagicMock
    ) -> None:
        """Failure on one finding does not prevent enrichment of subsequent findings."""
        mock_store.list_findings.return_value = [
            _make_finding(id="f1"),
            _make_finding(id="f2"),  # will fail
            _make_finding(id="f3"),
        ]
        good = _make_mock_response()
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.side_effect = [good, RuntimeError("oops"), good]
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 2
        assert mock_store.patch_finding.call_count == 2

    def test_failed_finding_not_patched(self, mock_store: MagicMock) -> None:
        """patch_finding is NOT called for a finding whose API call failed."""
        mock_store.list_findings.return_value = [_make_finding(id="fail-me")]
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.side_effect = RuntimeError("boom")
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                Enricher(store=mock_store).enrich("owner/repo")
        mock_store.patch_finding.assert_not_called()

    def test_missing_sdk_emits_warning_returns_zero(self, mock_store: MagicMock) -> None:
        """When anthropic SDK is absent, a warning is emitted and 0 is returned."""
        mock_store.list_findings.return_value = [_make_finding(id="f1")]
        with patch.dict("sys.modules", {"anthropic": None}):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                count = Enricher(store=mock_store).enrich("owner/repo")
        assert count == 0
        assert any("anthropic" in str(w.message).lower() for w in caught)

    def test_missing_sdk_does_not_call_patch_finding(self, mock_store: MagicMock) -> None:
        """When the SDK is absent, patch_finding is never called."""
        mock_store.list_findings.return_value = [_make_finding(id="f1")]
        with patch.dict("sys.modules", {"anthropic": None}):
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                Enricher(store=mock_store).enrich("owner/repo")
        mock_store.patch_finding.assert_not_called()


# ---------------------------------------------------------------------------
# Enricher — constructor options forwarded correctly
# ---------------------------------------------------------------------------


class TestEnricherConstructorOptions:
    """Tests that constructor options (api_key, model) are forwarded to the API."""

    @pytest.fixture()
    def mock_store(self) -> MagicMock:
        store = MagicMock()
        store.list_findings.return_value = [_make_finding(id="f1")]
        return store

    def test_api_key_forwarded_to_client(self, mock_store: MagicMock) -> None:
        """api_key is passed to anthropic.Anthropic(api_key=...)."""
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            MockClient.return_value.messages.create.return_value = _make_mock_response()
            Enricher(store=mock_store, api_key="test-key-123").enrich("owner/repo")
        MockClient.assert_called_once_with(api_key="test-key-123")

    def test_none_api_key_forwarded(self, mock_store: MagicMock) -> None:
        """api_key=None is forwarded (lets SDK read ANTHROPIC_API_KEY from env)."""
        with patch("anthropic.Anthropic") as MockClient:
            MockClient.return_value = MagicMock()
            MockClient.return_value.messages.create.return_value = _make_mock_response()
            Enricher(store=mock_store, api_key=None).enrich("owner/repo")
        MockClient.assert_called_once_with(api_key=None)

    def test_model_forwarded_to_messages_create(self, mock_store: MagicMock) -> None:
        """The configured model is passed to client.messages.create()."""
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            Enricher(store=mock_store, model="claude-opus-4-6").enrich("owner/repo")
        call_kwargs = mock_client.messages.create.call_args
        assert call_kwargs.kwargs["model"] == "claude-opus-4-6"

    def test_default_model_is_haiku(self, mock_store: MagicMock) -> None:
        """The default model sent to the API is DEFAULT_MODEL."""
        with patch("anthropic.Anthropic") as MockClient:
            mock_client = MagicMock()
            MockClient.return_value = mock_client
            mock_client.messages.create.return_value = _make_mock_response()
            Enricher(store=mock_store).enrich("owner/repo")
        call_kwargs = mock_client.messages.create.call_args
        assert call_kwargs.kwargs["model"] == DEFAULT_MODEL


# ---------------------------------------------------------------------------
# _parse_enrichment_response
# ---------------------------------------------------------------------------


class TestParseEnrichmentResponse:
    """Tests for the _parse_enrichment_response helper."""

    def test_valid_json_returns_correct_fields(self) -> None:
        text = json.dumps({"reasoning_extended": "reason", "remediation_sketch": "fix"})
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "reason"
        assert result["remediation_sketch"] == "fix"

    def test_markdown_json_fence_stripped(self) -> None:
        text = '```json\n{"reasoning_extended": "r", "remediation_sketch": "s"}\n```'
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "r"
        assert result["remediation_sketch"] == "s"

    def test_plain_code_fence_stripped(self) -> None:
        text = '```\n{"reasoning_extended": "r", "remediation_sketch": "s"}\n```'
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "r"

    def test_invalid_json_preserved_as_reasoning_extended(self) -> None:
        """When JSON parse fails, raw text becomes reasoning_extended."""
        raw = "This is not JSON at all."
        result = _parse_enrichment_response(raw)
        assert result["reasoning_extended"] == raw

    def test_invalid_json_leaves_remediation_empty(self) -> None:
        result = _parse_enrichment_response("not json")
        assert result["remediation_sketch"] == ""

    def test_empty_json_object_returns_empty_strings(self) -> None:
        result = _parse_enrichment_response("{}")
        assert result["reasoning_extended"] == ""
        assert result["remediation_sketch"] == ""

    def test_extra_keys_in_json_are_ignored(self) -> None:
        text = json.dumps(
            {"reasoning_extended": "r", "remediation_sketch": "s", "extra": "ignored"}
        )
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "r"
        assert result["remediation_sketch"] == "s"

    def test_non_string_values_coerced_to_string(self) -> None:
        text = json.dumps({"reasoning_extended": 42, "remediation_sketch": None})
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "42"
        assert result["remediation_sketch"] == "None"

    def test_whitespace_trimmed_before_parse(self) -> None:
        text = "  \n" + json.dumps({"reasoning_extended": "r", "remediation_sketch": "s"}) + "\n  "
        result = _parse_enrichment_response(text)
        assert result["reasoning_extended"] == "r"


# ---------------------------------------------------------------------------
# _calculate_cost
# ---------------------------------------------------------------------------


class TestCalculateCost:
    """Tests for the _calculate_cost helper."""

    def test_known_model_input_cost(self) -> None:
        """1 million input tokens for haiku → $0.80."""
        cost = _calculate_cost(DEFAULT_MODEL, input_tokens=1_000_000, output_tokens=0)
        assert cost == pytest.approx(0.80)

    def test_known_model_output_cost(self) -> None:
        """1 million output tokens for haiku → $4.00."""
        cost = _calculate_cost(DEFAULT_MODEL, input_tokens=0, output_tokens=1_000_000)
        assert cost == pytest.approx(4.00)

    def test_combined_input_and_output_cost(self) -> None:
        cost = _calculate_cost(DEFAULT_MODEL, input_tokens=100, output_tokens=50)
        expected = 100 * 8e-7 + 50 * 4e-6
        assert cost == pytest.approx(expected)

    def test_unknown_model_uses_fallback_rates(self) -> None:
        """Unknown model falls back to haiku pricing, so result matches known model."""
        cost_known = _calculate_cost(DEFAULT_MODEL, input_tokens=200, output_tokens=80)
        cost_unknown = _calculate_cost("some-future-model", input_tokens=200, output_tokens=80)
        assert cost_known == pytest.approx(cost_unknown)

    def test_zero_tokens_zero_cost(self) -> None:
        cost = _calculate_cost(DEFAULT_MODEL, input_tokens=0, output_tokens=0)
        assert cost == 0.0

    def test_cost_increases_with_more_tokens(self) -> None:
        small = _calculate_cost(DEFAULT_MODEL, input_tokens=100, output_tokens=100)
        large = _calculate_cost(DEFAULT_MODEL, input_tokens=1000, output_tokens=1000)
        assert large > small
