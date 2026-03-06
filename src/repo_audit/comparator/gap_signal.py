"""GapSignal dataclass for the comparator module."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GapSignal:
    """A single detected gap between two adjacent audit layers.

    Attributes:
        layer: Which layer comparison produced this signal, e.g.
            ``"declared_vs_structural"``.
        kind: The category of gap, e.g. ``"undocumented_module"`` or
            ``"unreachable_module"``.
        subject: The specific item (module name, script name, goal text)
            that exhibits the gap.
        evidence: Supporting details explaining why the gap was flagged.
    """

    layer: str
    kind: str
    subject: str
    evidence: list[str] = field(default_factory=list)
