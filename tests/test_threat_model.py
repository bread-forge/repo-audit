"""Tests for repo_audit.security.threat_model.ThreatModelAgent."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from repo_audit.security.threat_model import (
    ThreatModelAgent,
    _build_user_message,
    _normalize_severity,
    _normalize_staleness,
    _parse_llm_response,
    _threat_to_bead,
)


# ---------------------------------------------------------------------------
# _normalize_severity
# ---------------------------------------------------------------------------


class TestNormalizeSeverity:
    """Tests for _normalize_severity."""

    def test_valid_critical(self) -> None:
        assert _normalize_severity("critical") == "critical"

    def test_valid_high(self) -> None:
        assert _normalize_severity("high") == "high"

    def test_uppercase_lowercased(self) -> None:
        assert _normalize_severity("HIGH") == "high"

    def test_unknown_falls_back_to_medium(self) -> None:
        assert _normalize_severity("bogus") == "medium"

    def test_empty_falls_back_to_medium(self) -> None:
        assert _normalize_severity("") == "medium"


# ---------------------------------------------------------------------------
# _normalize_staleness
# ---------------------------------------------------------------------------


class TestNormalizeStaleness:
    """Tests for _normalize_staleness."""

    def test_valid_architectural(self) -> None:
        assert _normalize_staleness("architectural") == "architectural"

    def test_uppercase_lowercased(self) -> None:
        assert _normalize_staleness("CRITICAL") == "critical"

    def test_unknown_falls_back_to_structural(self) -> None:
        assert _normalize_staleness("unknown-class") == "structural"


# ---------------------------------------------------------------------------
# _build_user_message
# ---------------------------------------------------------------------------


class TestBuildUserMessage:
    """Tests for _build_user_message."""

    def test_readme_section_present(self) -> None:
        msg = _build_user_message("readme content", None, [])
        assert "=== README.md ===" in msg
        assert "readme content" in msg

    def test_readme_absent_shows_placeholder(self) -> None:
        msg = _build_user_message(None, None, [])
        assert "(not present)" in msg

    def test_claude_md_section_present(self) -> None:
        msg = _build_user_message(None, "claude content", [])
        assert "=== CLAUDE.md ===" in msg
        assert "claude content" in msg

    def test_entry_points_listed(self) -> None:
        msg = _build_user_message(None, None, ["myapp.cli", "myapp.server"])
        assert "myapp.cli" in msg
        assert "myapp.server" in msg

    def test_no_entry_points_shows_placeholder(self) -> None:
        msg = _build_user_message(None, None, [])
        assert "(none detected)" in msg


# ---------------------------------------------------------------------------
# _threat_to_bead
# ---------------------------------------------------------------------------


class TestThreatToBead:
    """Tests for _threat_to_bead."""

    SAMPLE_THREAT = {
        "summary": "SQL injection via unescaped user input",
        "severity": "high",
        "staleness_class": "structural",
        "reasoning": "The query builder does not sanitize user-supplied values.",
        "evidence": ["db.py:45", "user_input not validated"],
    }

    def test_returns_bead_with_correct_summary(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert bead.summary == "SQL injection via unescaped user input"

    def test_returns_none_for_empty_summary(self) -> None:
        threat = {**self.SAMPLE_THREAT, "summary": ""}
        assert _threat_to_bead(threat, repo_path="/repo", cycle_id="c1") is None

    def test_returns_none_for_missing_summary(self) -> None:
        threat = {k: v for k, v in self.SAMPLE_THREAT.items() if k != "summary"}
        assert _threat_to_bead(threat, repo_path="/repo", cycle_id="c1") is None

    def test_severity_normalized(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert bead.severity == "high"

    def test_staleness_class_propagated(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert bead.staleness_class == "structural"

    def test_agent_name(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert bead.agent == "security-scan-llm"

    def test_evidence_chain_populated(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert "db.py:45" in bead.evidence_chain

    def test_id_is_16_hex_chars(self) -> None:
        bead = _threat_to_bead(self.SAMPLE_THREAT, repo_path="/repo", cycle_id="c1")
        assert bead is not None
        assert len(bead.id) == 16


# ---------------------------------------------------------------------------
# _parse_llm_response
# ---------------------------------------------------------------------------


class TestParseLlmResponse:
    """Tests for _parse_llm_response."""

    SAMPLE_RESPONSE = json.dumps(
        [
            {
                "summary": "Insecure deserialization",
                "severity": "critical",
                "staleness_class": "structural",
                "reasoning": "Pickle loads untrusted data.",
                "evidence": ["loader.py:10"],
            }
        ]
    )

    def test_parses_valid_json_array(self) -> None:
        findings = _parse_llm_response(self.SAMPLE_RESPONSE, repo_path="/r", cycle_id="c")
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_strips_markdown_fences(self) -> None:
        fenced = f"```json\n{self.SAMPLE_RESPONSE}\n```"
        findings = _parse_llm_response(fenced, repo_path="/r", cycle_id="c")
        assert len(findings) == 1

    def test_strips_plain_code_fences(self) -> None:
        fenced = f"```\n{self.SAMPLE_RESPONSE}\n```"
        findings = _parse_llm_response(fenced, repo_path="/r", cycle_id="c")
        assert len(findings) == 1

    def test_invalid_json_returns_empty(self) -> None:
        findings = _parse_llm_response("not json", repo_path="/r", cycle_id="c")
        assert findings == []

    def test_non_array_returns_empty(self) -> None:
        findings = _parse_llm_response('{"key": "value"}', repo_path="/r", cycle_id="c")
        assert findings == []

    def test_empty_array_returns_empty(self) -> None:
        findings = _parse_llm_response("[]", repo_path="/r", cycle_id="c")
        assert findings == []

    def test_non_dict_entries_skipped(self) -> None:
        payload = json.dumps([1, "string", {"summary": "real threat", "severity": "low"}])
        findings = _parse_llm_response(payload, repo_path="/r", cycle_id="c")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# ThreatModelAgent.scan — key behaviour: skips when no API key
# ---------------------------------------------------------------------------


class TestThreatModelAgentSkipsWithoutApiKey:
    """ThreatModelAgent must return [] when ANTHROPIC_API_KEY is absent."""

    def test_returns_empty_when_env_var_unset(self, tmp_path: Path) -> None:
        """With no env var and no api_key arg, scan() returns an empty list."""
        env_without_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        agent = ThreatModelAgent(api_key=None)
        with patch.dict(os.environ, env_without_key, clear=True):
            findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_returns_empty_when_env_var_empty_string(self, tmp_path: Path) -> None:
        """Empty-string ANTHROPIC_API_KEY is treated as absent."""
        agent = ThreatModelAgent(api_key=None)
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            # Remove the key entirely if set, or set empty
            env_copy = {**os.environ, "ANTHROPIC_API_KEY": ""}
            with patch.dict(os.environ, env_copy, clear=True):
                findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_explicit_api_key_bypasses_env_check(self, tmp_path: Path) -> None:
        """When api_key is passed directly, the env var is not required.

        We don't make a real API call — the anthropic SDK import is mocked to
        raise ImportError so the agent skips cleanly without hitting the network.
        """
        env_without_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        agent = ThreatModelAgent(api_key="sk-fake-key-for-test")
        with patch.dict(os.environ, env_without_key, clear=True):
            with patch.dict("sys.modules", {"anthropic": None}):
                # anthropic not importable => returns []
                findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_api_failure_returns_empty(self, tmp_path: Path) -> None:
        """Any exception from the API call results in an empty list."""
        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value.messages.create.side_effect = RuntimeError(
            "network error"
        )
        agent = ThreatModelAgent(api_key="sk-test")
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []

    def test_sdk_not_installed_returns_empty(self, tmp_path: Path) -> None:
        """ImportError for anthropic SDK => empty list, no exception raised."""
        agent = ThreatModelAgent(api_key="sk-test")
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            with patch.dict("sys.modules", {"anthropic": None}):
                findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []


# ---------------------------------------------------------------------------
# ThreatModelAgent.scan — successful path (mocked API)
# ---------------------------------------------------------------------------


class TestThreatModelAgentScan:
    """Tests for the full scan() path with a mocked Anthropic client."""

    def _make_mock_anthropic(self, response_text: str) -> MagicMock:
        mock_content = MagicMock()
        mock_content.text = response_text
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_module = MagicMock()
        mock_module.Anthropic.return_value = mock_client
        return mock_module

    def test_returns_findings_from_llm_response(self, tmp_path: Path) -> None:
        """A valid LLM JSON response is parsed into FindingBead instances."""
        llm_json = json.dumps(
            [
                {
                    "summary": "Hardcoded credentials in source",
                    "severity": "high",
                    "staleness_class": "critical",
                    "reasoning": "Credentials are embedded in the source code.",
                    "evidence": ["config.py:5"],
                }
            ]
        )
        mock_anthropic = self._make_mock_anthropic(llm_json)
        agent = ThreatModelAgent(api_key="sk-test")
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                findings = agent.scan(tmp_path, cycle_id="c1")

        assert len(findings) == 1
        assert findings[0].summary == "Hardcoded credentials in source"
        assert findings[0].severity == "high"
        assert findings[0].agent == "security-scan-llm"

    def test_empty_llm_response_returns_empty_list(self, tmp_path: Path) -> None:
        mock_anthropic = self._make_mock_anthropic("[]")
        agent = ThreatModelAgent(api_key="sk-test")
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                findings = agent.scan(tmp_path, cycle_id="c1")
        assert findings == []
