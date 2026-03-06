"""Clusterer — groups FindingBeads into related clusters using union-find.

Two findings are connected when their ``blast_radius.modules_affected`` share at
least one module.  Connected components are extracted via union-find, then any
component exceeding ``MAX_CLUSTER_SIZE`` findings is split into sorted sub-groups
(by finding id).  The final list is returned in deterministic order: sorted by
the minimum finding id within each cluster.
"""

from __future__ import annotations

from collections import defaultdict

from repo_audit.verdict.finding_bead import FindingBead

MAX_CLUSTER_SIZE = 5


def _modules_affected(finding: FindingBead) -> frozenset[str]:
    """Return the set of modules affected by a finding.

    Uses ``getattr`` so the function is safe to call even when ``FindingBead``
    does not yet carry a ``blast_radius`` attribute (returns empty set).
    """
    blast_radius = getattr(finding, "blast_radius", None)
    if blast_radius is None:
        return frozenset()
    modules = getattr(blast_radius, "modules_affected", None)
    if not modules:
        return frozenset()
    return frozenset(modules)


def _find(parent: list[int], i: int) -> int:
    """Return the root of node *i* with path-halving compression."""
    while parent[i] != i:
        parent[i] = parent[parent[i]]  # point to grandparent (path halving)
        i = parent[i]
    return i


def _union(parent: list[int], i: int, j: int) -> None:
    """Merge the components containing nodes *i* and *j*."""
    ri, rj = _find(parent, i), _find(parent, j)
    if ri != rj:
        parent[ri] = rj


def _split_component(members: list[FindingBead]) -> list[list[FindingBead]]:
    """Split a component into sub-groups of at most MAX_CLUSTER_SIZE, preserving order."""
    return [
        members[start : start + MAX_CLUSTER_SIZE]
        for start in range(0, len(members), MAX_CLUSTER_SIZE)
    ]


def cluster_findings(findings: list[FindingBead]) -> list[list[FindingBead]]:
    """Group findings into clusters based on shared modules in their blast radius.

    Algorithm:
    1. Build a union-find structure over all findings.
    2. Connect two findings when their ``blast_radius.modules_affected`` sets
       share at least one module.
    3. Extract connected components; sort each component's members by finding id.
    4. Split any component that exceeds ``MAX_CLUSTER_SIZE`` into consecutive
       sub-groups of at most ``MAX_CLUSTER_SIZE`` findings (sorted by finding id).
    5. Sort the final list of clusters by the minimum (first) finding id in each
       cluster, producing a fully deterministic output ordering.

    Args:
        findings: The list of :class:`~repo_audit.verdict.finding_bead.FindingBead`
            objects to cluster.

    Returns:
        A list of clusters.  Each cluster is a non-empty list of
        :class:`~repo_audit.verdict.finding_bead.FindingBead` objects sorted by
        finding id.  Clusters themselves are sorted by their minimum finding id.
        Returns an empty list when *findings* is empty.
    """
    if not findings:
        return []

    n = len(findings)
    parent = list(range(n))
    modules_per_finding = [_modules_affected(f) for f in findings]

    for i in range(n):
        for j in range(i + 1, n):
            if modules_per_finding[i] & modules_per_finding[j]:
                _union(parent, i, j)

    component_map: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        component_map[_find(parent, i)].append(i)

    clusters: list[list[FindingBead]] = []
    for indices in component_map.values():
        indices.sort(key=lambda i: findings[i].id)
        members = [findings[i] for i in indices]
        clusters.extend(_split_component(members))

    clusters.sort(key=lambda cluster: cluster[0].id)
    return clusters
