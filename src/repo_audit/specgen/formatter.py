"""Formatter — converts a cluster of FindingBeads into a kiln Markdown spec file.

Each cluster is rendered as a self-contained Markdown file with YAML front-matter
that lists the source finding IDs, the union of all affected modules (blast radius),
a priority derived from the highest severity in the cluster, and an empty
``depends_on`` list.  Five body sections follow: Overview, Goals, Modules,
Validation, and Meta.
"""

from __future__ import annotations

from repo_audit.verdict.finding_bead import FindingBead, Severity

# ---------------------------------------------------------------------------
# Severity → kiln priority mapping
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_SEVERITY_TO_PRIORITY: dict[Severity, str] = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _modules_affected(finding: FindingBead) -> frozenset[str]:
    """Return the set of modules affected by a finding.

    Uses ``getattr`` so the function is safe when ``FindingBead`` does not
    carry a ``blast_radius`` attribute (returns empty frozenset).
    """
    blast_radius = getattr(finding, "blast_radius", None)
    if blast_radius is None:
        return frozenset()
    modules = getattr(blast_radius, "modules_affected", None)
    if not modules:
        return frozenset()
    return frozenset(modules)


def _highest_severity(cluster: list[FindingBead]) -> Severity:
    """Return the highest severity across all findings in the cluster.

    Falls back to ``"low"`` when the cluster is empty.
    """
    if not cluster:
        return "low"
    return max((f.severity for f in cluster), key=lambda s: _SEVERITY_RANK.get(s, 0))


def _blast_radius_modules(cluster: list[FindingBead]) -> list[str]:
    """Return a sorted list of unique modules affected by any finding in the cluster."""
    all_modules: set[str] = set()
    for finding in cluster:
        all_modules.update(_modules_affected(finding))
    return sorted(all_modules)


def _yaml_string_list(items: list[str]) -> str:
    """Render a YAML block sequence of strings, or an inline ``[]`` when empty."""
    if not items:
        return "[]"
    lines = "\n".join(f"  - {item}" for item in items)
    return f"\n{lines}"


def _render_front_matter(
    source_findings: list[str],
    blast_radius: list[str],
    priority: str,
) -> str:
    """Render YAML front-matter between ``---`` delimiters."""
    findings_block = _yaml_string_list(source_findings)
    blast_block = _yaml_string_list(blast_radius)
    return (
        f"---\n"
        f"source_findings:{findings_block}\n"
        f"blast_radius:{blast_block}\n"
        f"priority: {priority}\n"
        f"depends_on: []\n"
        f"---"
    )


def _render_overview(cluster: list[FindingBead], blast_radius: list[str]) -> str:
    """Render the ## Overview section body."""
    n = len(cluster)
    finding_word = "finding" if n == 1 else "findings"
    module_count = len(blast_radius)

    summary = (
        f"This cluster contains {n} {finding_word} "
        f"with a combined blast radius spanning {module_count} module(s)."
    )
    if blast_radius:
        module_list = ", ".join(f"`{m}`" for m in blast_radius)
        summary += f" Affected modules: {module_list}."
    return summary


def _render_goals(cluster: list[FindingBead]) -> str:
    """Render the ## Goals section body as a bullet list of finding summaries."""
    if not cluster:
        return "_(no findings)_"
    return "\n".join(f"- {f.summary}" for f in cluster)


def _render_modules(blast_radius: list[str]) -> str:
    """Render the ## Modules section body as a bullet list of module names."""
    if not blast_radius:
        return "_(no modules identified)_"
    return "\n".join(f"- `{m}`" for m in blast_radius)


def _render_validation() -> str:
    """Render the ## Validation section with stub shell command placeholders."""
    return "```sh\n# TODO: add validation commands\n```"


def _render_meta(cluster: list[FindingBead], cluster_index: int) -> str:
    """Render the ## Meta section with per-finding metadata rows."""
    rows = [f"- **Cluster index:** {cluster_index}"]
    for finding in cluster:
        rows.append(
            f"- `{finding.id}` — severity: {finding.severity},"
            f" staleness: {finding.staleness_class},"
            f" agent: {finding.agent}"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def format_spec(cluster: list[FindingBead], cluster_index: int) -> tuple[str, str]:
    """Format a cluster of findings as a kiln Markdown spec file.

    Args:
        cluster: Non-empty list of :class:`~repo_audit.verdict.finding_bead.FindingBead`
            objects that form a single cluster.
        cluster_index: Zero-based index of this cluster within the full cluster list,
            used to construct a deterministic filename and to label the Meta section.

    Returns:
        A ``(filename, content)`` tuple where *filename* follows the pattern
        ``spec-cluster-NNN.md`` and *content* is a valid kiln Markdown file:
        YAML front-matter (``source_findings``, ``blast_radius``, ``priority``,
        ``depends_on``) followed by ``## Overview``, ``## Goals``, ``## Modules``,
        ``## Validation``, and ``## Meta`` sections.
    """
    filename = f"spec-cluster-{cluster_index:03d}.md"

    source_findings = [f.id for f in cluster]
    blast_radius = _blast_radius_modules(cluster)
    priority = _SEVERITY_TO_PRIORITY[_highest_severity(cluster)]

    front_matter = _render_front_matter(source_findings, blast_radius, priority)
    overview = _render_overview(cluster, blast_radius)
    goals = _render_goals(cluster)
    modules = _render_modules(blast_radius)
    validation = _render_validation()
    meta = _render_meta(cluster, cluster_index)

    content = "\n\n".join(
        [
            front_matter,
            f"## Overview\n\n{overview}",
            f"## Goals\n\n{goals}",
            f"## Modules\n\n{modules}",
            f"## Validation\n\n{validation}",
            f"## Meta\n\n{meta}",
        ]
    )
    # Ensure a single trailing newline.
    content = content.rstrip("\n") + "\n"

    return filename, content
