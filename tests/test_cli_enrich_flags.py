"""Tests for the --enrich/--no-enrich/--re-enrich CLI flags on the `run` command.

All tests mock the heavy-lifting pipeline components (harvest, analyze, compare,
verdict, store, Enricher) and focus exclusively on the enrichment control flow:
- --enrich  → Enricher is created and enrich() is called
- --no-enrich → Enricher is never called
- --re-enrich → existing enrichment is cleared before enrich() is called
- auto-detect (no flag) with ANTHROPIC_API_KEY set → Enricher is called
- auto-detect (no flag) with ANTHROPIC_API_KEY absent → Enricher is not called
- --model → correct model is forwarded to the Enricher constructor
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Stub 'beads' before any repo_audit import.
if "beads" not in sys.modules:
    sys.modules["beads"] = MagicMock()

from typer.testing import CliRunner  # noqa: E402

from repo_audit.cli import _should_enrich, app  # noqa: E402
from repo_audit.enricher.enricher import DEFAULT_MODEL  # noqa: E402
from repo_audit.verdict.finding_bead import FindingBead  # noqa: E402

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_repo"

runner = CliRunner()


# ---------------------------------------------------------------------------
# _should_enrich helper
# ---------------------------------------------------------------------------


class TestShouldEnrich:
    """Tests for the _should_enrich helper that interprets the flag + env."""

    def test_explicit_true_returns_true(self) -> None:
        assert _should_enrich(True) is True

    def test_explicit_false_returns_false(self) -> None:
        assert _should_enrich(False) is False

    def test_none_with_key_set_returns_true(self) -> None:
        """Auto-detect: ANTHROPIC_API_KEY present → enrich."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            assert _should_enrich(None) is True

    def test_none_with_key_absent_returns_false(self) -> None:
        """Auto-detect: ANTHROPIC_API_KEY absent → skip."""
        with patch.dict("os.environ", {}, clear=True):
            # Ensure the key is definitely absent even if set in the outer env.
            import os

            env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
            with patch.dict("os.environ", env, clear=True):
                assert _should_enrich(None) is False

    def test_none_with_empty_key_returns_false(self) -> None:
        """An empty ANTHROPIC_API_KEY is falsy → skip enrichment."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}):
            assert _should_enrich(None) is False


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------


def _make_enriched_finding(id: str) -> FindingBead:
    return FindingBead(
        id=id,
        agent="a",
        severity="medium",
        staleness_class="structural",
        confidence=0.8,
        evidence_chain=[],
        reasoning="r",
        cycle_id="20240101T000000Z",
        repo_path="/tmp/repo",
        summary="s",
        reasoning_extended="existing analysis",
        remediation_sketch="existing sketch",
    )


def _run_with_enrich_patches(
    tmp_path: Path,
    args: list[str],
    mock_store: MagicMock,
    mock_enricher_cls: MagicMock | None = None,
) -> object:
    """Invoke the `run` CLI command with all pipeline components mocked."""
    patches = [
        patch("repo_audit.cli.CACHE_DIR", tmp_path / "cache"),
        patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
        patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
    ]
    if mock_enricher_cls is not None:
        patches.append(patch("repo_audit.cli.Enricher", mock_enricher_cls))

    with (
        patch("repo_audit.cli.CACHE_DIR", tmp_path / "cache"),
        patch("repo_audit.cli.RepoAuditStore", return_value=mock_store),
        patch("repo_audit.cli._derive_repo_slug", return_value="owner/repo"),
        patch("repo_audit.cli.Enricher", mock_enricher_cls or MagicMock()),
    ):
        return runner.invoke(app, ["run", str(FIXTURE_REPO)] + args)


# ---------------------------------------------------------------------------
# --no-enrich: Enricher must not be invoked
# ---------------------------------------------------------------------------


class TestNoEnrichFlag:
    """Tests that --no-enrich prevents enrichment regardless of env."""

    def test_no_enrich_flag_exits_0(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        result = _run_with_enrich_patches(tmp_path, ["--no-enrich"], mock_store, mock_enricher_cls)
        assert result.exit_code == 0

    def test_no_enrich_does_not_call_enricher(self, tmp_path: Path) -> None:
        """--no-enrich must not instantiate or call Enricher."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        _run_with_enrich_patches(tmp_path, ["--no-enrich"], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_not_called()

    def test_no_enrich_overrides_env_key(self, tmp_path: Path) -> None:
        """--no-enrich suppresses enrichment even when ANTHROPIC_API_KEY is set."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-present"}):
            _run_with_enrich_patches(tmp_path, ["--no-enrich"], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_not_called()


# ---------------------------------------------------------------------------
# --enrich: Enricher must be invoked
# ---------------------------------------------------------------------------


class TestEnrichFlag:
    """Tests that --enrich triggers enrichment."""

    def test_enrich_flag_exits_0(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        result = _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)
        assert result.exit_code == 0

    def test_enrich_flag_instantiates_enricher(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_called_once()

    def test_enrich_flag_calls_enrich_with_slug(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)
        mock_enricher_instance.enrich.assert_called_once_with("owner/repo")

    def test_enrich_flag_prints_enriched_count(self, tmp_path: Path) -> None:
        """Output must mention the number of enriched findings."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 5
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        result = _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)
        assert "5" in result.output

    def test_enrich_flag_overrides_missing_env_key(self, tmp_path: Path) -> None:
        """--enrich triggers enrichment even when ANTHROPIC_API_KEY is absent."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        import os

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict("os.environ", env, clear=True):
            _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_called_once()


# ---------------------------------------------------------------------------
# Auto-detect (no explicit flag)
# ---------------------------------------------------------------------------


class TestEnrichAutoDetect:
    """Tests for automatic enrichment detection based on ANTHROPIC_API_KEY."""

    def test_auto_detect_enriches_when_key_set(self, tmp_path: Path) -> None:
        """No explicit flag + ANTHROPIC_API_KEY present → Enricher is called."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-present"}):
            _run_with_enrich_patches(tmp_path, [], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_called_once()

    def test_auto_detect_skips_when_key_absent(self, tmp_path: Path) -> None:
        """No explicit flag + ANTHROPIC_API_KEY absent → Enricher is not called."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        import os

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict("os.environ", env, clear=True):
            _run_with_enrich_patches(tmp_path, [], mock_store, mock_enricher_cls)
        mock_enricher_cls.assert_not_called()

    def test_auto_detect_skip_exits_0(self, tmp_path: Path) -> None:
        """run exits 0 with no enrichment output when key is absent."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        import os

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict("os.environ", env, clear=True):
            result = _run_with_enrich_patches(tmp_path, [], mock_store, mock_enricher_cls)
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# --re-enrich: clear existing enrichment, then enrich
# ---------------------------------------------------------------------------


class TestReEnrichFlag:
    """Tests for --re-enrich: clears existing enrichment fields before re-enriching."""

    def test_re_enrich_clears_existing_enrichment(self, tmp_path: Path) -> None:
        """--re-enrich calls patch_finding to clear reasoning_extended for enriched findings."""
        mock_store = MagicMock()
        enriched = _make_enriched_finding("f-enriched")
        # list_findings returns the same list every time (before and after clearing)
        mock_store.list_findings.return_value = [enriched]
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 1
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(
            tmp_path, ["--enrich", "--re-enrich"], mock_store, mock_enricher_cls
        )

        # patch_finding should have been called to clear the enrichment fields.
        patch_calls = mock_store.patch_finding.call_args_list
        clear_calls = [c for c in patch_calls if c.kwargs.get("reasoning_extended") is None]
        assert len(clear_calls) >= 1

    def test_re_enrich_passes_none_for_all_enrichment_fields(self, tmp_path: Path) -> None:
        """The clear call sets reasoning_extended, remediation_sketch, and enrichment_cost_usd to None."""
        mock_store = MagicMock()
        enriched = _make_enriched_finding("f1")
        mock_store.list_findings.return_value = [enriched]
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 1
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(
            tmp_path, ["--enrich", "--re-enrich"], mock_store, mock_enricher_cls
        )

        patch_calls = mock_store.patch_finding.call_args_list
        clear_calls = [
            c
            for c in patch_calls
            if c.kwargs.get("reasoning_extended") is None
            and c.kwargs.get("remediation_sketch") is None
            and c.kwargs.get("enrichment_cost_usd") is None
        ]
        assert len(clear_calls) >= 1

    def test_re_enrich_then_calls_enricher(self, tmp_path: Path) -> None:
        """After clearing, Enricher.enrich() is still called."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = [_make_enriched_finding("f1")]
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 1
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(
            tmp_path, ["--enrich", "--re-enrich"], mock_store, mock_enricher_cls
        )

        mock_enricher_instance.enrich.assert_called_once_with("owner/repo")

    def test_re_enrich_does_not_clear_unenriched_findings(self, tmp_path: Path) -> None:
        """Findings without reasoning_extended are not touched by the clear step."""
        mock_store = MagicMock()
        unenriched = FindingBead(
            id="new",
            agent="a",
            severity="low",
            staleness_class="structural",
            confidence=0.5,
            evidence_chain=[],
            reasoning="r",
            cycle_id="20240101T000000Z",
            repo_path="/tmp/repo",
            summary="s",
            reasoning_extended=None,
        )
        mock_store.list_findings.return_value = [unenriched]
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 1
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(
            tmp_path, ["--enrich", "--re-enrich"], mock_store, mock_enricher_cls
        )

        # patch_finding should NOT have been called to clear this finding.
        clear_calls = [
            c
            for c in mock_store.patch_finding.call_args_list
            if c.args[1] == "new" and c.kwargs.get("reasoning_extended") is None
        ]
        assert len(clear_calls) == 0

    def test_re_enrich_without_enrich_flag_is_noop(self, tmp_path: Path) -> None:
        """--re-enrich without --enrich: enrichment is not triggered if key absent."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()
        import os

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict("os.environ", env, clear=True):
            result = _run_with_enrich_patches(
                tmp_path, ["--re-enrich"], mock_store, mock_enricher_cls
            )
        assert result.exit_code == 0
        mock_enricher_cls.assert_not_called()


# ---------------------------------------------------------------------------
# --model flag
# ---------------------------------------------------------------------------


class TestModelFlag:
    """Tests that --model forwards the correct model to the Enricher."""

    def test_model_flag_forwarded_to_enricher(self, tmp_path: Path) -> None:
        """--model value is passed to Enricher(model=...)."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(
            tmp_path,
            ["--enrich", "--model", "claude-opus-4-6"],
            mock_store,
            mock_enricher_cls,
        )

        call_kwargs = mock_enricher_cls.call_args.kwargs
        assert call_kwargs["model"] == "claude-opus-4-6"

    def test_default_model_is_used_without_flag(self, tmp_path: Path) -> None:
        """Without --model, Enricher receives DEFAULT_MODEL."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_instance = MagicMock()
        mock_enricher_instance.enrich.return_value = 0
        mock_enricher_cls = MagicMock(return_value=mock_enricher_instance)

        _run_with_enrich_patches(tmp_path, ["--enrich"], mock_store, mock_enricher_cls)

        call_kwargs = mock_enricher_cls.call_args.kwargs
        assert call_kwargs["model"] == DEFAULT_MODEL

    def test_model_flag_accepted_with_no_enrich(self, tmp_path: Path) -> None:
        """--model with --no-enrich is accepted (exit 0, Enricher not called)."""
        mock_store = MagicMock()
        mock_store.list_findings.return_value = []
        mock_enricher_cls = MagicMock()

        result = _run_with_enrich_patches(
            tmp_path,
            ["--no-enrich", "--model", "claude-haiku-4-5-20251001"],
            mock_store,
            mock_enricher_cls,
        )
        assert result.exit_code == 0
        mock_enricher_cls.assert_not_called()
