"""Dedup — skip spec generation for findings already covered by existing specs.

Two public functions:

* :func:`load_covered_finding_ids` — scan an output directory for previously
  generated spec files and collect all finding ids they reference.
* :func:`filter_new_clusters` — remove clusters that overlap with the already-
  covered set so that only genuinely new work is passed to the formatter.
"""

from __future__ import annotations

import re
from pathlib import Path

from repo_audit.verdict.finding_bead import FindingBead

# Matches a YAML front-matter block at the start of a file:
#   ---\n<content>\n---
_FRONT_MATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)

# Matches a list item line under source_findings, e.g. "  - abc123ef"
_LIST_ITEM_RE = re.compile(r"^\s+-\s+(\S+)$")


def _parse_source_findings(text: str) -> list[str]:
    """Extract the ``source_findings`` id list from a YAML front-matter string.

    Handles only the subset of YAML produced by this project's formatter:

    .. code-block:: yaml

        source_findings:
          - <id>
          - <id>

    Returns an empty list when the key is absent or the block is malformed.
    """
    ids: list[str] = []
    in_source_findings = False
    for line in text.splitlines():
        if re.match(r"^source_findings\s*:", line):
            in_source_findings = True
            continue
        if in_source_findings:
            item_match = _LIST_ITEM_RE.match(line)
            if item_match:
                ids.append(item_match.group(1))
            elif line and not line[0].isspace():
                # A new top-level key; stop collecting.
                break
    return ids


def load_covered_finding_ids(out_dir: Path) -> set[str]:
    """Return all finding ids referenced in spec files under *out_dir*.

    Globs ``out_dir/*.md``, parses the YAML front-matter from each file, and
    collects every entry in ``source_findings`` into a flat set.

    Files that have no front-matter or no ``source_findings`` key are skipped
    silently.

    Args:
        out_dir: Directory that contains previously generated ``.md`` spec files.

    Returns:
        A set of finding id strings.  Empty when *out_dir* does not exist or
        contains no spec files with ``source_findings`` front-matter.
    """
    covered: set[str] = set()
    for spec_file in out_dir.glob("*.md"):
        raw = spec_file.read_text(encoding="utf-8")
        match = _FRONT_MATTER_RE.match(raw)
        if not match:
            continue
        front_matter = match.group(1)
        covered.update(_parse_source_findings(front_matter))
    return covered


def filter_new_clusters(
    clusters: list[list[FindingBead]],
    covered_ids: set[str],
) -> list[list[FindingBead]]:
    """Return only clusters that are not already covered by existing specs.

    A cluster is considered *covered* when any of its finding ids appears in
    *covered_ids* (non-empty intersection).  Such clusters are dropped from the
    output so the formatter only processes genuinely new findings.

    Args:
        clusters: Clusters produced by
            :func:`~repo_audit.specgen.clusterer.cluster_findings`.
        covered_ids: Set of finding ids already present in generated spec files,
            typically obtained from :func:`load_covered_finding_ids`.

    Returns:
        The subset of *clusters* whose finding ids have no overlap with
        *covered_ids*, preserving the original order.  Returns an empty list
        when all clusters are covered or *clusters* is empty.
    """
    if not covered_ids:
        return list(clusters)
    return [
        cluster
        for cluster in clusters
        if not any(finding.id in covered_ids for finding in cluster)
    ]
