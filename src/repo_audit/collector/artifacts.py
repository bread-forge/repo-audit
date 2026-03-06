"""Dataclass for collected repository artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CollectedArtifacts:
    """All artifacts harvested from a repository.

    Every field holds only JSON-serializable types (str, dict, list, None)
    so the struct can be serialised without a custom encoder.
    """

    readme: Optional[str] = None
    """Content of README.md, or None if the file is absent."""

    claude_md: Optional[str] = None
    """Content of CLAUDE.md, or None if the file is absent."""

    specs: dict[str, str] = field(default_factory=dict)
    """Contents of specs/*.md files, keyed by path relative to the repo root."""

    docs: dict[str, str] = field(default_factory=dict)
    """Contents of docs/**/*.md files, keyed by path relative to the repo root."""

    docstrings: dict[str, Optional[str]] = field(default_factory=dict)
    """Module-level docstrings from .py files, keyed by path relative to the repo root.

    The value is None when the module has no docstring or when the file could not
    be parsed (e.g. syntax errors).
    """

    entry_points: dict[str, str] = field(default_factory=dict)
    """Console-script entry points from [project.scripts] in pyproject.toml.

    Keys are script names; values are the ``module:callable`` strings.
    """
