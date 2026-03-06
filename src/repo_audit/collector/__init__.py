"""Collector module: harvest repository artifacts into a structured dataclass."""

from .artifacts import CollectedArtifacts
from .harvester import harvest

__all__ = ["CollectedArtifacts", "harvest"]
