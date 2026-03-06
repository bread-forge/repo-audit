"""RepoAuditStore — thin BeadStore wrapper for repo-audit artifact persistence.

Layout (mirroring BeadStore's directory convention):
  ~/.repo-audit/beads/<owner>/<repo>/artifacts.json   CollectedArtifacts
  ~/.repo-audit/beads/<owner>/<repo>/analysis.json    AnalysisResult

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

DEFAULT_BEADS_DIR = Path.home() / ".repo-audit" / "beads"


class RepoAuditStore:
    """Persists collector artifacts and analyzer results via BeadStore.

    Each repo_slug gets its own BeadStore instance (and therefore its own
    directory subtree under beads_dir).  Artifacts and analysis are stored as
    plain JSON files alongside the BeadStore-managed files.
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
    # Internal helpers
    # ------------------------------------------------------------------

    def _artifacts_path(self, repo_slug: str) -> Path:
        owner, name = repo_slug.split("/", 1)
        return self._beads_dir / owner / name / "artifacts.json"

    def _analysis_path(self, repo_slug: str) -> Path:
        owner, name = repo_slug.split("/", 1)
        return self._beads_dir / owner / name / "analysis.json"


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
