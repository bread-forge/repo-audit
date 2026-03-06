"""Gitleaks secret-scanning wrapper for repo-audit.

Wraps the ``gitleaks`` CLI to detect exposed secrets in a repository and
normalises each finding into a :class:`~repo_audit.verdict.finding_bead.FindingBead`
with ``severity='critical'`` and ``staleness_class='critical'``.

Evidence stored in the finding is limited to the file path and line number of
the leak — the secret value itself is **never** captured or stored.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from repo_audit.verdict.finding_bead import FindingBead

AGENT_NAME = "gitleaks"

# gitleaks exits with 1 when secrets are found, 0 when none are found.
_EXIT_LEAKS_FOUND = 1
_EXIT_NO_LEAKS = 0

# Confidence for a gitleaks match: pattern-based detection is reliable but
# subject to false positives, so we cap at 0.8 rather than using the evidence-
# count formula used elsewhere.
_CONFIDENCE = 0.8


def _finding_id(fingerprint: str) -> str:
    """Derive a deterministic 16-character hex ID from *fingerprint*."""
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


def _bead_from_finding(
    finding: dict[str, Any],
    repo: str,
    cycle_id: str,
) -> FindingBead:
    """Convert a single gitleaks finding dict into a :class:`FindingBead`.

    Only the file path and start line are stored in ``evidence_chain`` —
    the secret match and value are intentionally excluded.

    Args:
        finding: Parsed JSON object from gitleaks output.
        repo: Filesystem path to the audited repository.
        cycle_id: Identifier of the audit cycle.

    Returns:
        A :class:`FindingBead` with ``severity='critical'`` and
        ``staleness_class='critical'``.
    """
    file_path: str = finding.get("File", "")
    start_line: int = finding.get("StartLine", 0)
    rule_id: str = finding.get("RuleID", "unknown-rule")
    description: str = finding.get("Description", "Secret detected")

    # Fingerprint uniquely identifies the finding; fall back to a composite key.
    fingerprint: str = finding.get("Fingerprint", f"{file_path}:{start_line}:{rule_id}")

    # Evidence: location only — never the secret value.
    evidence = [f"{file_path}:{start_line}"]

    summary = f"Secret detected ({rule_id}): {file_path}"
    reasoning = (
        f"Gitleaks matched rule '{rule_id}' ({description}) "
        f"at {file_path} line {start_line}. "
        "Evidence stores location only; the secret value is not recorded."
    )

    return FindingBead(
        id=_finding_id(fingerprint),
        agent=AGENT_NAME,
        severity="critical",
        staleness_class="critical",
        confidence=_CONFIDENCE,
        evidence_chain=evidence,
        reasoning=reasoning,
        cycle_id=cycle_id,
        repo_path=repo,
        summary=summary,
    )


class GitleaksScanner:
    """Runs ``gitleaks detect`` against a repository and returns findings.

    Usage::

        scanner = GitleaksScanner()
        findings = scanner.scan("/path/to/repo")
    """

    def scan(self, repo_path: str | Path) -> list[FindingBead]:
        """Invoke ``gitleaks detect`` on *repo_path* and return findings.

        The command run is::

            gitleaks detect --source . --report-format json --report-path -

        executed with *repo_path* as the working directory.

        Returns an empty list when:

        * ``gitleaks`` is not installed (``FileNotFoundError``).
        * gitleaks exits with a code other than 0 or 1 (tool error).
        * gitleaks reports no findings.

        Args:
            repo_path: Absolute or relative path to the repository root.

        Returns:
            List of :class:`FindingBead` instances, one per secret found.
        """
        path = Path(repo_path)

        try:
            result = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    ".",
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                ],
                capture_output=True,
                text=True,
                cwd=str(path),
            )
        except FileNotFoundError:
            # gitleaks is not installed — treat as no findings rather than error.
            return []

        if result.returncode not in (_EXIT_NO_LEAKS, _EXIT_LEAKS_FOUND):
            # Tool error (bad flags, permission denied, etc.) — skip silently.
            return []

        return self.parse_output(result.stdout, repo=str(path), cycle_id="")

    def parse_output(
        self,
        jsonl_or_json_str: str,
        repo: str,
        cycle_id: str,
    ) -> list[FindingBead]:
        """Parse gitleaks JSON (or JSONL) output into :class:`FindingBead` instances.

        Supports two formats emitted by gitleaks:

        * **JSON array** — ``[{...}, {...}]`` (default ``--report-format json``).
        * **JSONL** — one JSON object per line (alternative format).

        Secret values from the raw gitleaks output are **never** propagated
        into the returned beads.

        Args:
            jsonl_or_json_str: Raw stdout from ``gitleaks detect``.
            repo: Filesystem path to the audited repository.
            cycle_id: Identifier of the audit cycle.

        Returns:
            List of :class:`FindingBead` instances, one per valid finding.
        """
        raw = jsonl_or_json_str.strip()
        if not raw or raw == "null":
            return []

        findings: list[dict[str, Any]] = _parse_findings(raw)
        return [_bead_from_finding(f, repo, cycle_id) for f in findings]


def _parse_findings(raw: str) -> list[dict[str, Any]]:
    """Attempt to parse *raw* as a JSON array, single object, or JSONL.

    Returns a list of finding dicts.  Malformed entries are skipped.
    """
    # Try JSON array / single object first (most common gitleaks output).
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [f for f in parsed if isinstance(f, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []
    except json.JSONDecodeError:
        pass

    # Fall back to JSONL (one object per line).
    findings: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            findings.append(obj)
    return findings
