"""Four-layer gap analysis between adjacent audit representations.

Each function compares one adjacent pair of audit layers and returns a list of
:class:`~repo_audit.comparator.gap_signal.GapSignal` instances describing the
gaps it found.

Layer order (coarsest to finest):
    declared → structural → behavioral → activated
    (+ test coverage cross-check against declared)
"""

from __future__ import annotations

import re

from repo_audit.analyzer.result import AnalysisResult
from repo_audit.collector.artifacts import CollectedArtifacts
from repo_audit.comparator.gap_signal import GapSignal

# ---------------------------------------------------------------------------
# Layer name constants
# ---------------------------------------------------------------------------

LAYER_DECLARED_VS_STRUCTURAL = "declared_vs_structural"
LAYER_STRUCTURAL_VS_BEHAVIORAL = "structural_vs_behavioral"
LAYER_BEHAVIORAL_VS_ACTIVATED = "behavioral_vs_activated"
LAYER_TEST_VS_DECLARED = "test_vs_declared"

# ---------------------------------------------------------------------------
# Regex patterns for layer 4
# ---------------------------------------------------------------------------

# Matches markdown headings that introduce Goals or Validation sections.
_GOAL_SECTION_RE = re.compile(
    r"^#{1,6}\s+(?:Goals?|Validation|Requirements?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Matches a markdown heading of any level (used to find the end of a section).
_ANY_HEADING_RE = re.compile(r"^#{1,6}\s", re.MULTILINE)

# Matches a markdown bullet item line.
_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.+)$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _module_path_suffixes(module_name: str) -> tuple[str, str]:
    """Return the two candidate file-path suffixes for a dotted module name.

    For ``"foo.bar"`` returns ``("foo/bar.py", "foo/bar/__init__.py")``.
    """
    path_prefix = module_name.replace(".", "/")
    return f"{path_prefix}.py", f"{path_prefix}/__init__.py"


def _find_docstring_for_module(
    module_name: str,
    docstrings: dict[str, str | None],
) -> tuple[bool, str | None]:
    """Look up the module-level docstring for *module_name*.

    Returns:
        ``(found, docstring)`` where *found* is True when the module's source
        file appears in *docstrings* (even if its docstring is None).
    """
    a_suffix, b_suffix = _module_path_suffixes(module_name)
    for key, docstring in docstrings.items():
        normalized = key.replace("\\", "/")
        if (
            normalized in (a_suffix, b_suffix)
            or normalized.endswith(f"/{a_suffix}")
            or normalized.endswith(f"/{b_suffix}")
        ):
            return True, docstring
    return False, None


def _extract_goal_assertions(text: str) -> list[str]:
    """Extract bullet items from Goals/Validation/Requirements sections.

    Scans *text* for headings that match :data:`_GOAL_SECTION_RE` and collects
    every bullet item under each such heading until the next heading.

    Returns:
        List of stripped bullet-item strings.  Empty list if no matching
        sections are found.
    """
    assertions: list[str] = []
    for section_match in _GOAL_SECTION_RE.finditer(text):
        section_start = section_match.end()
        # Find the next heading after this section to bound the search.
        next_heading = _ANY_HEADING_RE.search(text, section_start)
        section_end = next_heading.start() if next_heading else len(text)
        section_body = text[section_start:section_end]
        for bullet in _BULLET_RE.finditer(section_body):
            assertions.append(bullet.group(1).strip())
    return assertions


def _test_modules_in_graph(import_graph: dict[str, list[str]]) -> list[str]:
    """Return all module names in *import_graph* that look like test modules."""
    return [
        name for name in import_graph if any(part.startswith("test") for part in name.split("."))
    ]


def _modules_imported_by_tests(
    test_modules: list[str],
    import_graph: dict[str, list[str]],
) -> set[str]:
    """Collect the union of all modules directly imported by test modules."""
    tested: set[str] = set()
    for test_mod in test_modules:
        tested.update(import_graph.get(test_mod, []))
    return tested


# ---------------------------------------------------------------------------
# Layer 1: declared vs structural
# ---------------------------------------------------------------------------


def declared_vs_structural(
    artifacts: CollectedArtifacts,
    analysis: AnalysisResult,
) -> list[GapSignal]:
    """Compare documentation (declared) against the import graph (structural).

    A module is considered *declared* when its source file has a non-None
    module-level docstring.  Every module discovered by the AST walker is
    *structural*.  Modules that exist structurally but carry no docstring
    are flagged as undocumented gaps.

    Args:
        artifacts: Harvested collector artifacts, including ``docstrings``.
        analysis: AST analysis result containing the ``import_graph``.

    Returns:
        One :class:`GapSignal` per undocumented module in the import graph.
    """
    signals: list[GapSignal] = []
    for module_name in sorted(analysis.import_graph):
        found, docstring = _find_docstring_for_module(module_name, artifacts.docstrings)
        if found and docstring is None:
            signals.append(
                GapSignal(
                    layer=LAYER_DECLARED_VS_STRUCTURAL,
                    kind="undocumented_module",
                    subject=module_name,
                    evidence=[f"Module {module_name!r} exists but has no module-level docstring"],
                )
            )
        elif not found:
            # Module in import graph with no corresponding collector entry —
            # likely a dependency or virtual module; skip.
            pass
    return signals


# ---------------------------------------------------------------------------
# Layer 2: structural vs behavioral
# ---------------------------------------------------------------------------


def structural_vs_behavioral(analysis: AnalysisResult) -> list[GapSignal]:
    """Compare the full import graph (structural) against reachable modules (behavioral).

    Every module present in the import graph but absent from the reachable set
    is unreachable from any declared entry point.  These modules represent code
    that is structurally present but behaviourally dead.

    Args:
        analysis: AST analysis result with ``import_graph`` and
            ``reachable_from_entry_points``.

    Returns:
        One :class:`GapSignal` per module in the graph that is not reachable
        from any entry point.
    """
    reachable: set[str] = set(analysis.reachable_from_entry_points)
    signals: list[GapSignal] = []
    for module_name in sorted(analysis.import_graph):
        if module_name not in reachable:
            signals.append(
                GapSignal(
                    layer=LAYER_STRUCTURAL_VS_BEHAVIORAL,
                    kind="unreachable_module",
                    subject=module_name,
                    evidence=[
                        f"Module {module_name!r} is present in the import graph"
                        " but not reachable from any entry point"
                    ],
                )
            )
    return signals


# ---------------------------------------------------------------------------
# Layer 3: behavioral vs activated
# ---------------------------------------------------------------------------


def behavioral_vs_activated(
    artifacts: CollectedArtifacts,
    analysis: AnalysisResult,
) -> list[GapSignal]:
    """Compare CLI-wired entry points (activated) against the import graph (behavioral).

    Each ``[project.scripts]`` entry in ``pyproject.toml`` names a
    ``module:callable`` target.  When the module portion of that target is
    absent from the import graph the entry point is broken — it is activated
    in configuration but has no corresponding code.

    Args:
        artifacts: Harvested collector artifacts, including ``entry_points``.
        analysis: AST analysis result containing the ``import_graph``.

    Returns:
        One :class:`GapSignal` per entry point whose target module is missing
        from the import graph.
    """
    signals: list[GapSignal] = []
    for script_name, target in sorted(artifacts.entry_points.items()):
        module_part = target.split(":")[0]
        if not module_part:
            continue
        if module_part not in analysis.import_graph:
            signals.append(
                GapSignal(
                    layer=LAYER_BEHAVIORAL_VS_ACTIVATED,
                    kind="broken_entry_point",
                    subject=script_name,
                    evidence=[
                        f"Entry point {script_name!r} targets {target!r}",
                        f"Module {module_part!r} not found in import graph",
                    ],
                )
            )
    return signals


# ---------------------------------------------------------------------------
# Layer 4: test vs declared
# ---------------------------------------------------------------------------


def test_vs_declared(
    artifacts: CollectedArtifacts,
    analysis: AnalysisResult,
) -> list[GapSignal]:
    """Check that spec Goals/Validation assertions have test-module coverage.

    Scans all spec and doc files for headings named *Goals*, *Validation*, or
    *Requirements* and extracts their bullet items as *declared assertions*.
    It then checks whether test modules (modules whose name contains ``test``)
    exist in the import graph and import the modules that the assertions
    reference.

    When a declared assertion cannot be associated with a specific module (no
    recognisable module name appears in the assertion text), the check falls
    back to verifying that *any* test module exists.

    Args:
        artifacts: Harvested collector artifacts, including ``specs``,
            ``docs``, and ``entry_points``.
        analysis: AST analysis result containing the ``import_graph``.

    Returns:
        One :class:`GapSignal` per declared assertion that lacks test coverage.
    """
    assertions: list[tuple[str, str]] = []  # (source_path, assertion_text)
    for source_path, text in list(artifacts.specs.items()) + list(artifacts.docs.items()):
        for item in _extract_goal_assertions(text):
            assertions.append((source_path, item))

    if not assertions:
        return []

    test_modules = _test_modules_in_graph(analysis.import_graph)
    tested_modules = _modules_imported_by_tests(test_modules, analysis.import_graph)

    signals: list[GapSignal] = []
    for source_path, assertion_text in assertions:
        # Try to find a module name referenced in the assertion by matching
        # it against known modules (longest match wins to prefer sub-modules).
        referenced_module = _find_referenced_module(assertion_text, analysis.import_graph)

        if referenced_module is not None:
            if referenced_module not in tested_modules:
                signals.append(
                    GapSignal(
                        layer=LAYER_TEST_VS_DECLARED,
                        kind="untested_goal",
                        subject=assertion_text,
                        evidence=[
                            f"Declared in {source_path!r}",
                            f"References module {referenced_module!r}"
                            " which is not imported by any test module",
                        ],
                    )
                )
        else:
            # No specific module identified — fall back: any test module is enough.
            if not test_modules:
                signals.append(
                    GapSignal(
                        layer=LAYER_TEST_VS_DECLARED,
                        kind="untested_goal",
                        subject=assertion_text,
                        evidence=[
                            f"Declared in {source_path!r}",
                            "No test modules found in the import graph",
                        ],
                    )
                )

    return signals


def _find_referenced_module(
    text: str,
    import_graph: dict[str, list[str]],
) -> str | None:
    """Return the longest module name from *import_graph* mentioned in *text*.

    Checks for backtick-quoted names (`` `foo` ``) first, then plain words.
    Returns the best (longest) match, or None when nothing matches.
    """
    # Extract candidate names: backtick-quoted identifiers take priority.
    backtick_names = re.findall(r"`([A-Za-z_][A-Za-z0-9_.]*)`", text)
    word_names = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", text)
    candidates = backtick_names + word_names

    best: str | None = None
    for candidate in candidates:
        for module_name in import_graph:
            leaf = module_name.split(".")[-1]
            if leaf == candidate or module_name == candidate:
                if best is None or len(module_name) > len(best):
                    best = module_name
    return best
