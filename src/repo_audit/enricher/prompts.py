"""System prompt and user message builder for the enricher LLM calls."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_audit.verdict.finding_bead import FindingBead

SYSTEM_PROMPT = """\
You are a code quality and security analysis assistant. You receive structured \
code audit findings and provide two forms of expert commentary:

1. **Extended reasoning** — a detailed technical explanation of why the finding \
matters: its root cause, potential impact, and any relevant context about the \
patterns or practices involved.

2. **Remediation sketch** — a concrete, actionable suggestion for how to address \
the finding. This should be specific enough for a developer to act on, but \
does not need to be full working code.

Respond ONLY with a JSON object matching this exact schema — no prose, no \
markdown fences, no extra keys:

{
  "reasoning_extended": "<detailed explanation>",
  "remediation_sketch": "<actionable fix suggestion>"
}"""


def build_user_message(finding: FindingBead) -> str:
    """Serialize a FindingBead into the user message sent to the LLM.

    The finding is rendered as a JSON object so the model has all evidence
    and context fields available in a structured form.
    """
    payload = {
        "id": finding.id,
        "agent": finding.agent,
        "severity": finding.severity,
        "staleness_class": finding.staleness_class,
        "confidence": finding.confidence,
        "summary": finding.summary,
        "reasoning": finding.reasoning,
        "evidence_chain": finding.evidence_chain,
        "repo_path": finding.repo_path,
    }
    return (
        "Please analyse the following code audit finding and produce the "
        "extended reasoning and remediation sketch described in the system prompt.\n\n"
        + json.dumps(payload, indent=2)
    )
