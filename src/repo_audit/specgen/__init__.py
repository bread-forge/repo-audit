"""specgen — spec generation utilities for repo-audit findings.

Public API re-exported from sub-modules for convenience.
"""

from repo_audit.specgen.clusterer import MAX_CLUSTER_SIZE, cluster_findings

__all__ = ["cluster_findings", "MAX_CLUSTER_SIZE"]
