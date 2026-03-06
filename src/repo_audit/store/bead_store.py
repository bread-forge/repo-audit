"""RepoAuditStore — thin BeadStore wrapper for repo-audit artifact persistence.

Layout (mirroring BeadStore's directory convention):
  ~/.repo-audit/beads/<owner>/<repo>/artifacts.json   CollectedArtifacts
  ~/.repo-audit/beads/<owner>/<repo>/analysis.json    AnalysisResult
  ~/.repo-audit/beads/<owner>/<repo>/findings.json    list of FindingBead

All writes are atomic (write-to-tmp + os.replace) via BeadStore's convention.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from beads import BeadStore

if TYPE_CHECKING:
    from repo_audit.analyzer.result import AnalysisResult
    from repo_audit.collector.artifacts import CollectedArtifacts
    from repo_audit.verdict.finding_bead import FindingBead

DEFAULT_BEADS_DIR = Path.home() / ".repo-audit" / "beads"

# Severity ordering — higher rank means higher severity.
_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class RepoAuditStore:
    """Persists collector artifacts, analyzer results, and findings via BeadStore.

    Each repo_slug gets its own BeadStore instance (and therefore its own
    directory subtree under beads_dir).  Artifacts, analysis, and findings are
    stored as plain JSON files alongside the BeadStore-managed files.
    """

    def __init__(self, beads_dir: Path = DEFAULT_BEADS_DIR) -> None:
        self._beads_dir = beads_dir

    # ------------------------------------------------------------------
    # CollectedArtifacts
    # ------------------------------------------------------------------

    def save_artifacts(self, repo_slug: str, artifacts: CollectedArtifacts) -> None:
        """Serialize CollectedArtifacts and write atomically to the bead store."""
        _validate_slug(repo_slug)
        _init_bead_store(self._beads_dir, repo_slug)
        _atomic_write(self._artifacts_path(repo_slug), dataclasses.asdict(artifacts))

    def load_artifacts(self, repo_slug: str) -> CollectedArtifacts | None:
        """Deserialize CollectedArtifacts from the bead store.

        Returns None if no artifacts have been saved for this repo_slug.
        """
        _validate_slug(repo_slug)
        path = self._artifacts_path(repo_slug)
        if not path.exists():
            return None
        # Lazy import: collector module is a separate PR and not present at
        # store-module build time; it will be importable at runtime.
        from repo_audit.collector.artifacts import CollectedArtifacts as CA

        data = json.loads(path.read_text(encoding="utf-8"))
        return CA(**data)

    # ------------------------------------------------------------------
    # AnalysisResult
    # ------------------------------------------------------------------

    def save_analysis(self, repo_slug: str, result: AnalysisResult) -> None:
        """Serialize AnalysisResult and write atomically to the bead store."""
        _validate_slug(repo_slug)
        _init_bead_store(self._beads_dir, repo_slug)
        _atomic_write(self._analysis_path(repo_slug), dataclasses.asdict(result))

    def load_analysis(self, repo_slug: str) -> AnalysisResult | None:
        """Deserialize AnalysisResult from the bead store.

        Returns None if no analysis has been saved for this repo_slug.
        """
        _validate_slug(repo_slug)
        path = self._analysis_path(repo_slug)
        if not path.exists():
            return None
        # Lazy import: analyzer module is a separate PR and not present at
        # store-module build time; it will be importable at runtime.
        from repo_audit.analyzer.result import AnalysisResult as AR

        data = json.loads(path.read_text(encoding="utf-8"))
        return AR(**data)

    # ------------------------------------------------------------------
    # FindingBead
    # ------------------------------------------------------------------

    def save_finding(self, repo_slug: str, finding: FindingBead) -> None:
        """Append a FindingBead to findings.json for this repo_slug.

        Findings accumulate across runs; each call appends one entry.
        """
        _validate_slug(repo_slug)
        _init_bead_store(self._beads_dir, repo_slug)
        path = self._findings_path(repo_slug)
        stored = self._load_findings_envelope(path)
        stored["findings"].append(dataclasses.asdict(finding))
        _atomic_write(path, stored)

    def list_findings(
        self,
        repo_slug: str,
        min_severity: str = "low",
        since_cycle_id: str | None = None,
    ) -> list[FindingBead]:
        """Return FindingBeads for repo_slug, filtered by severity and cycle.

        Args:
            repo_slug: Repository identifier in ``owner/repo`` format.
            min_severity: Include only findings at or above this severity level.
                Must be one of ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
            since_cycle_id: When provided, return only findings whose
                ``cycle_id`` is strictly greater than this value (delta mode).
                Cycle IDs are UTC timestamp strings that sort lexicographically.

        Returns:
            Filtered list of :class:`~repo_audit.verdict.finding_bead.FindingBead`
            instances in the order they were saved.
        """
        # Lazy import: verdict module is a separate PR and not present at
        # store-module build time; it will be importable at runtime.
        from repo_audit.verdict.finding_bead import FindingBead as FB

        _validate_slug(repo_slug)
        path = self._findings_path(repo_slug)
        envelope = self._load_findings_envelope(path)

        min_rank = _SEVERITY_RANK.get(min_severity, 0)
        results: list[FB] = []
        for item in envelope["findings"]:
            bead = FB(**item)
            if _SEVERITY_RANK.get(bead.severity, 0) < min_rank:
                continue
            if since_cycle_id is not None and bead.cycle_id <= since_cycle_id:
                continue
            results.append(bead)
        return results

    def patch_finding(
        self,
        repo_slug: str,
        finding_id: str,
        **updates: object,
    ) -> None:
        """Apply partial field updates to an existing stored finding.

        Only the fields named in *updates* are changed; all other fields
        retain their current values.  This is intended for the enricher module
        to populate ``reasoning_extended``, ``remediation_sketch``, and
        ``enrichment_cost_usd`` after initial scoring.

        Args:
            repo_slug: Repository identifier in ``owner/repo`` format.
            finding_id: The ``id`` of the finding to update.
            **updates: Keyword arguments mapping field names to new values.
                Valid keys are any field defined on
                :class:`~repo_audit.verdict.finding_bead.FindingBead`.

        Raises:
            ValueError: If *repo_slug* is not in ``owner/repo`` format.
            ValueError: If no finding with *finding_id* exists in the store.
        """
        _validate_slug(repo_slug)
        path = self._findings_path(repo_slug)
        envelope = self._load_findings_envelope(path)
        for item in envelope["findings"]:
            if item.get("id") == finding_id:
                item.update(updates)
                _atomic_write(path, envelope)
                return
        raise ValueError(f"Finding {finding_id!r} not found in {repo_slug!r}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _artifacts_path(self, repo_slug: str) -> Path:
        owner, name = repo_slug.split("/", 1)
        return self._beads_dir / owner / name / "artifacts.json"

    def _analysis_path(self, repo_slug: str) -> Path:
        owner, name = repo_slug.split("/", 1)
        return self._beads_dir / owner / name / "analysis.json"

    def _findings_path(self, repo_slug: str) -> Path:
        owner, name = repo_slug.split("/", 1)
        return self._beads_dir / owner / name / "findings.json"

    def _load_findings_envelope(self, path: Path) -> dict:
        """Return the findings envelope dict, or an empty one if the file is absent."""
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {"findings": []}


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _validate_slug(repo_slug: str) -> None:
    """Raise ValueError if repo_slug is not in 'owner/repo' format."""
    if "/" not in repo_slug:
        raise ValueError(f"repo_slug must be 'owner/repo', got: {repo_slug!r}")


def _init_bead_store(beads_dir: Path, repo_slug: str) -> BeadStore:
    """Instantiate a BeadStore for repo_slug, creating its directory layout."""
    return BeadStore(beads_dir=beads_dir, repo=repo_slug)


def _atomic_write(path: Path, data: dict) -> None:
    """Write data as JSON atomically using write-to-tmp + os.replace."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
