"""Tests for repo_audit.specgen.formatter.

Covers filename generation, required Markdown sections, YAML front-matter
key presence and correctness, priority mapping, and content details.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

from repo_audit.specgen.formatter import format_spec
from repo_audit.verdict.finding_bead import FindingBead


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str,
    severity: str = "low",
    modules: list[str] | None = None,
    summary: str = "",
    staleness_class: str = "structural",
    agent: str = "test-agent",
) -> FindingBead:
    """Build a minimal FindingBead, optionally attaching a blast_radius mock."""
    finding = FindingBead(
        id=id,
        agent=agent,
        severity=severity,  # type: ignore[arg-type]
        staleness_class=staleness_class,  # type: ignore[arg-type]
        confidence=0.5,
        summary=summary or f"Finding {id}",
    )
    if modules is not None:
        blast_radius = MagicMock()
        blast_radius.modules_affected = modules
        finding.blast_radius = blast_radius  # type: ignore[attr-defined]
    return finding


def _extract_front_matter_text(content: str) -> str:
    """Return the raw text between the opening and closing --- delimiters."""
    assert content.startswith("---\n"), "Spec file must start with YAML front-matter"
    end = content.index("\n---", 4)
    return content[4:end]


def _parse_list_key(fm_text: str, key: str) -> list[str]:
    """Parse a YAML block-sequence under *key* into a Python list of strings."""
    in_key = False
    items: list[str] = []
    for line in fm_text.splitlines():
        if re.match(rf"^{re.escape(key)}\s*:", line):
            in_key = True
            continue
        if in_key:
            m = re.match(r"^\s+-\s+(\S+)$", line)
            if m:
                items.append(m.group(1))
            elif line and not line[0].isspace():
                break
    return items


def _parse_scalar_key(fm_text: str, key: str) -> str | None:
    """Return the scalar value for *key* in the front-matter text, or None."""
    for line in fm_text.splitlines():
        m = re.match(rf"^{re.escape(key)}\s*:\s*(.+)$", line)
        if m:
            return m.group(1).strip()
    return None


def _has_key(fm_text: str, key: str) -> bool:
    """Return True when *key* appears as a top-level YAML key in *fm_text*."""
    return bool(re.search(rf"^{re.escape(key)}\s*:", fm_text, re.MULTILINE))


# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------


class TestFormatSpecFilename:
    """Filename produced by format_spec."""

    def test_cluster_index_zero_produces_correct_filename(self) -> None:
        """cluster_index=0 yields 'spec-cluster-000.md'."""
        f = _make_finding("abc")
        filename, _ = format_spec([f], 0)
        assert filename == "spec-cluster-000.md"

    def test_cluster_index_seven_pads_to_three_digits(self) -> None:
        """cluster_index=7 yields 'spec-cluster-007.md'."""
        f = _make_finding("abc")
        filename, _ = format_spec([f], 7)
        assert filename == "spec-cluster-007.md"

    def test_cluster_index_large_value(self) -> None:
        """cluster_index=42 yields 'spec-cluster-042.md'."""
        f = _make_finding("abc")
        filename, _ = format_spec([f], 42)
        assert filename == "spec-cluster-042.md"

    def test_different_indices_produce_unique_filenames(self) -> None:
        """Different cluster indices yield different filenames."""
        f = _make_finding("abc")
        fn0, _ = format_spec([f], 0)
        fn1, _ = format_spec([f], 1)
        fn2, _ = format_spec([f], 2)
        assert len({fn0, fn1, fn2}) == 3


# ---------------------------------------------------------------------------
# Required Markdown sections
# ---------------------------------------------------------------------------


class TestFormatSpecMarkdownSections:
    """All five required Markdown sections must be present."""

    def _cluster(self) -> list[FindingBead]:
        return [
            _make_finding("abc", severity="high", modules=["auth"], summary="Auth issue"),
            _make_finding("def", severity="medium", modules=["db"], summary="DB issue"),
        ]

    def test_overview_section_present(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        assert "## Overview" in content

    def test_goals_section_present(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        assert "## Goals" in content

    def test_modules_section_present(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        assert "## Modules" in content

    def test_validation_section_present(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        assert "## Validation" in content

    def test_meta_section_present(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        assert "## Meta" in content

    def test_all_five_sections_present_together(self) -> None:
        _, content = format_spec(self._cluster(), 0)
        for section in ("## Overview", "## Goals", "## Modules", "## Validation", "## Meta"):
            assert section in content, f"Missing section: {section}"


# ---------------------------------------------------------------------------
# YAML front-matter keys
# ---------------------------------------------------------------------------


class TestFormatSpecFrontMatterKeys:
    """Front-matter must contain exactly the required keys."""

    def test_source_findings_key_present(self) -> None:
        f = _make_finding("abc123")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _has_key(fm, "source_findings")

    def test_blast_radius_key_present(self) -> None:
        f = _make_finding("abc", modules=["auth"])
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _has_key(fm, "blast_radius")

    def test_priority_key_present(self) -> None:
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _has_key(fm, "priority")

    def test_depends_on_key_present(self) -> None:
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _has_key(fm, "depends_on")


# ---------------------------------------------------------------------------
# YAML front-matter values
# ---------------------------------------------------------------------------


class TestFormatSpecFrontMatterValues:
    """Front-matter values must be accurate."""

    def test_source_findings_contains_finding_id(self) -> None:
        f = _make_finding("abc123ef")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        ids = _parse_list_key(fm, "source_findings")
        assert "abc123ef" in ids

    def test_source_findings_contains_all_ids_in_cluster(self) -> None:
        a = _make_finding("aaaa1111")
        b = _make_finding("bbbb2222")
        _, content = format_spec([a, b], 0)
        fm = _extract_front_matter_text(content)
        ids = _parse_list_key(fm, "source_findings")
        assert set(ids) == {"aaaa1111", "bbbb2222"}

    def test_blast_radius_contains_affected_modules(self) -> None:
        f = _make_finding("abc", modules=["auth", "db"])
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        modules = _parse_list_key(fm, "blast_radius")
        assert set(modules) == {"auth", "db"}

    def test_blast_radius_union_across_cluster(self) -> None:
        """blast_radius lists the union of modules from all findings."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["db"])
        _, content = format_spec([a, b], 0)
        fm = _extract_front_matter_text(content)
        modules = _parse_list_key(fm, "blast_radius")
        assert set(modules) == {"auth", "db"}

    def test_depends_on_is_empty_inline_list(self) -> None:
        """depends_on is always the empty YAML inline list []."""
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        value = _parse_scalar_key(fm, "depends_on")
        assert value == "[]"

    def test_blast_radius_empty_when_no_modules(self) -> None:
        """blast_radius is an empty inline list when no finding has modules."""
        f = _make_finding("abc")  # no blast_radius
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        value = _parse_scalar_key(fm, "blast_radius")
        assert value == "[]"


# ---------------------------------------------------------------------------
# Priority mapping
# ---------------------------------------------------------------------------


class TestFormatSpecPriorityMapping:
    """Severity → priority mapping."""

    def test_critical_severity_maps_to_p0(self) -> None:
        f = _make_finding("abc", severity="critical")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P0"

    def test_high_severity_maps_to_p1(self) -> None:
        f = _make_finding("abc", severity="high")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P1"

    def test_medium_severity_maps_to_p2(self) -> None:
        f = _make_finding("abc", severity="medium")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P2"

    def test_low_severity_maps_to_p3(self) -> None:
        f = _make_finding("abc", severity="low")
        _, content = format_spec([f], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P3"

    def test_priority_derived_from_highest_severity_in_cluster(self) -> None:
        """Mixed severity cluster uses the highest severity for the priority."""
        low = _make_finding("aaa", severity="low")
        high = _make_finding("bbb", severity="high")
        _, content = format_spec([low, high], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P1"

    def test_priority_critical_dominates_all_others(self) -> None:
        """critical finding in a mixed cluster always yields P0."""
        crit = _make_finding("aaa", severity="critical")
        low = _make_finding("bbb", severity="low")
        med = _make_finding("ccc", severity="medium")
        _, content = format_spec([crit, low, med], 0)
        fm = _extract_front_matter_text(content)
        assert _parse_scalar_key(fm, "priority") == "P0"


# ---------------------------------------------------------------------------
# Body content
# ---------------------------------------------------------------------------


class TestFormatSpecBodyContent:
    """Body sections contain the expected content."""

    def test_goals_section_lists_finding_summaries(self) -> None:
        f = _make_finding("abc", summary="Fix the auth bug")
        _, content = format_spec([f], 0)
        assert "Fix the auth bug" in content

    def test_modules_section_lists_module_names(self) -> None:
        f = _make_finding("abc", modules=["auth", "db"])
        _, content = format_spec([f], 0)
        assert "`auth`" in content
        assert "`db`" in content

    def test_modules_section_stub_when_no_modules(self) -> None:
        """When no modules are identified, the stub message is shown."""
        f = _make_finding("abc")  # no modules
        _, content = format_spec([f], 0)
        assert "_(no modules identified)_" in content

    def test_meta_section_contains_cluster_index(self) -> None:
        f = _make_finding("abc")
        _, content = format_spec([f], 5)
        assert "Cluster index:** 5" in content

    def test_meta_section_contains_finding_id(self) -> None:
        f = _make_finding("deadbeef")
        _, content = format_spec([f], 0)
        assert "deadbeef" in content

    def test_meta_section_contains_severity(self) -> None:
        f = _make_finding("abc", severity="critical")
        _, content = format_spec([f], 0)
        assert "severity: critical" in content

    def test_overview_mentions_single_finding_word(self) -> None:
        """One finding uses the singular 'finding' in the overview."""
        f = _make_finding("abc", modules=["auth"])
        _, content = format_spec([f], 0)
        assert "1 finding" in content
        assert "1 findings" not in content

    def test_overview_mentions_plural_findings_word(self) -> None:
        """Two findings use the plural 'findings' in the overview."""
        a = _make_finding("aaa", modules=["auth"])
        b = _make_finding("bbb", modules=["auth"])
        _, content = format_spec([a, b], 0)
        assert "2 findings" in content

    def test_validation_section_has_stub_command(self) -> None:
        """Validation section contains the TODO placeholder."""
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        assert "# TODO: add validation commands" in content


# ---------------------------------------------------------------------------
# Trailing newline
# ---------------------------------------------------------------------------


class TestFormatSpecTrailingNewline:
    """Content must end with exactly one newline character."""

    def test_content_ends_with_single_newline(self) -> None:
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        assert content.endswith("\n")

    def test_content_does_not_end_with_double_newline(self) -> None:
        f = _make_finding("abc")
        _, content = format_spec([f], 0)
        assert not content.endswith("\n\n")
