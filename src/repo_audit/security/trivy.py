"""Trivy filesystem vulnerability scanner — wraps the trivy CLI.

Provides :class:`TrivyScanner` with two public methods:

* :meth:`TrivyScanner.scan` — invoke ``trivy fs`` against a repository path
  and return a list of :class:`~repo_audit.verdict.finding_bead.FindingBead`.
* :meth:`TrivyScanner.parse_output` — parse raw Trivy JSON into FindingBeads.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from repo_audit.verdict.finding_bead import FindingBead

TRIVY_AGENT = "trivy"
STALENESS_CLASS = "dependency"
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
DEFAULT_SEVERITY = "medium"


def _finding_id(cve_id: str, pkg_name: str) -> str:
    """Return a 16-character deterministic hex ID for a CVE + package pair."""
    raw = f"{cve_id}:{pkg_name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _normalize_severity(trivy_severity: str) -> str:
    """Lowercase and validate a Trivy severity string.

    Falls back to ``'medium'`` when the value is not one of the four
    recognised levels (critical, high, medium, low).
    """
    normalized = trivy_severity.lower()
    if normalized in VALID_SEVERITIES:
        return normalized
    return DEFAULT_SEVERITY


def _build_evidence_chain(vuln: dict[str, Any]) -> list[str]:
    """Build an ordered evidence list from a Trivy vulnerability dict.

    Includes up to three entries:
    1. ``CVE: <id>`` — the CVE identifier.
    2. ``Package: <name> <installed-version>`` — the affected package.
    3. ``Fixed in: <version>`` — the version that resolves the CVE, if known.
    """
    evidence: list[str] = []

    cve_id = vuln.get("VulnerabilityID", "")
    if cve_id:
        evidence.append(f"CVE: {cve_id}")

    pkg_name = vuln.get("PkgName", "")
    installed = vuln.get("InstalledVersion", "")
    if pkg_name:
        pkg_entry = f"Package: {pkg_name}"
        if installed:
            pkg_entry += f" {installed}"
        evidence.append(pkg_entry)

    fixed = vuln.get("FixedVersion", "")
    if fixed:
        evidence.append(f"Fixed in: {fixed}")

    return evidence


def _vuln_to_finding(vuln: dict[str, Any], repo: str, cycle_id: str) -> FindingBead:
    """Convert a single Trivy vulnerability dict to a :class:`FindingBead`."""
    cve_id = vuln.get("VulnerabilityID", "")
    pkg_name = vuln.get("PkgName", "")
    severity = _normalize_severity(vuln.get("Severity", ""))
    evidence = _build_evidence_chain(vuln)
    confidence = min(len(evidence) * 0.2, 0.95)

    # Use title, then description, then CVE ID as the human-readable reasoning.
    reasoning = vuln.get("Title", "") or vuln.get("Description", "") or cve_id

    if cve_id and pkg_name:
        summary = f"{cve_id}: {pkg_name}"
    elif cve_id:
        summary = cve_id
    else:
        summary = pkg_name

    return FindingBead(
        id=_finding_id(cve_id, pkg_name),
        agent=TRIVY_AGENT,
        severity=severity,
        staleness_class=STALENESS_CLASS,
        confidence=confidence,
        evidence_chain=evidence,
        reasoning=reasoning,
        cycle_id=cycle_id,
        repo_path=repo,
        summary=summary,
    )


class TrivyScanner:
    """Wrap the ``trivy`` CLI to scan a repository filesystem for CVEs.

    Usage::

        scanner = TrivyScanner()
        findings = scanner.scan("/path/to/repo", cycle_id="20240101T120000Z")
    """

    def scan(self, repo_path: str | Path, cycle_id: str = "") -> list[FindingBead]:
        """Run ``trivy fs . --format json`` under *repo_path* and return findings.

        Returns an empty list — without raising — when:

        * ``trivy`` is not installed (:exc:`FileNotFoundError`).
        * ``trivy`` exits with a non-zero code (:exc:`subprocess.CalledProcessError`).

        Args:
            repo_path: Filesystem path to the repository root to scan.
            cycle_id: Optional audit-cycle identifier propagated to each bead.

        Returns:
            A list of :class:`~repo_audit.verdict.finding_bead.FindingBead`, one
            per detected vulnerability.
        """
        try:
            result = subprocess.run(
                ["trivy", "fs", ".", "--format", "json"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError:
            return []
        except subprocess.CalledProcessError:
            return []

        return self.parse_output(result.stdout, str(repo_path), cycle_id)

    def parse_output(self, json_str: str, repo: str, cycle_id: str) -> list[FindingBead]:
        """Parse Trivy JSON output and return one :class:`FindingBead` per vulnerability.

        Each bead is produced with:

        * ``staleness_class = 'dependency'``
        * ``severity`` lowercased from Trivy's ``Severity`` field (falls back to
          ``'medium'`` for unrecognised values).
        * ``evidence_chain`` containing the CVE ID, affected package with installed
          version, and the fixed version (when available).

        Args:
            json_str: Raw Trivy JSON output (the ``stdout`` of a ``trivy fs`` run).
            repo: Filesystem path to the repository that was scanned.
            cycle_id: Audit-cycle identifier propagated to each bead.

        Returns:
            A list of :class:`~repo_audit.verdict.finding_bead.FindingBead`.
            Returns an empty list for invalid JSON or when no vulnerabilities are
            present.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return []

        findings: list[FindingBead] = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                findings.append(_vuln_to_finding(vuln, repo, cycle_id))

        return findings
