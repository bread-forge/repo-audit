"""Enricher — calls the Anthropic API to add extended analysis to FindingBeads."""

from __future__ import annotations

import json
import logging
import warnings
from typing import TYPE_CHECKING

from repo_audit.enricher.prompts import SYSTEM_PROMPT, build_user_message

if TYPE_CHECKING:
    from repo_audit.store.bead_store import RepoAuditStore
    from repo_audit.verdict.finding_bead import FindingBead

LOG = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_BATCH_SIZE = 10
MAX_TOKENS = 1024

# USD cost per token for known models.  The haiku-4-5 tier is priced at
# $0.80/MTok input and $4.00/MTok output (as of 2025-Q1).
_INPUT_COST_PER_TOKEN: dict[str, float] = {
    "claude-haiku-4-5-20251001": 8e-7,
}
_OUTPUT_COST_PER_TOKEN: dict[str, float] = {
    "claude-haiku-4-5-20251001": 4e-6,
}
# Fallback pricing when the model is not in the tables above.
_FALLBACK_INPUT_COST: float = 8e-7
_FALLBACK_OUTPUT_COST: float = 4e-6


class Enricher:
    """Enriches FindingBeads with extended reasoning and remediation sketches.

    Fetches unenriched findings from a :class:`~repo_audit.store.bead_store.RepoAuditStore`,
    sends each to the Anthropic Messages API in batches, and writes the
    ``reasoning_extended``, ``remediation_sketch``, and ``enrichment_cost_usd``
    fields back via :meth:`~repo_audit.store.bead_store.RepoAuditStore.patch_finding`.

    API unavailability (missing SDK, network errors, auth failures) is handled
    gracefully: a warning is emitted per failure and processing continues.

    Args:
        store: The bead store to read findings from and write enrichment back to.
        model: Anthropic model identifier.  Defaults to ``claude-haiku-4-5-20251001``.
        batch_size: Number of findings processed per batch iteration.  Defaults to 10.
        api_key: Anthropic API key.  When *None* the SDK reads ``ANTHROPIC_API_KEY``
            from the environment.
    """

    def __init__(
        self,
        store: RepoAuditStore,
        model: str = DEFAULT_MODEL,
        batch_size: int = DEFAULT_BATCH_SIZE,
        api_key: str | None = None,
    ) -> None:
        self._store = store
        self._model = model
        self._batch_size = batch_size
        self._api_key = api_key

    def enrich(self, repo_slug: str) -> int:
        """Enrich all unenriched findings for *repo_slug*.

        Only findings whose ``reasoning_extended`` field is ``None`` are
        processed; already-enriched findings are skipped.

        Args:
            repo_slug: Repository identifier in ``owner/repo`` format.

        Returns:
            Number of findings successfully enriched in this call.
        """
        try:
            import anthropic  # noqa: F401 — checked for availability only
        except ImportError:
            warnings.warn(
                "anthropic SDK is not installed; enrichment is unavailable. "
                "Install it with: pip install anthropic",
                stacklevel=2,
            )
            return 0

        import anthropic as _anthropic

        findings = self._store.list_findings(repo_slug)
        unenriched = [f for f in findings if f.reasoning_extended is None]

        if not unenriched:
            LOG.debug("No unenriched findings for %r; nothing to do.", repo_slug)
            return 0

        client = _anthropic.Anthropic(api_key=self._api_key)
        enriched_count = 0

        for batch_start in range(0, len(unenriched), self._batch_size):
            batch = unenriched[batch_start : batch_start + self._batch_size]
            for finding in batch:
                try:
                    result = self._call_api(client, finding)
                    self._store.patch_finding(
                        repo_slug,
                        finding.id,
                        reasoning_extended=result["reasoning_extended"],
                        remediation_sketch=result["remediation_sketch"],
                        enrichment_cost_usd=result["enrichment_cost_usd"],
                    )
                    enriched_count += 1
                    LOG.debug("Enriched finding %r.", finding.id)
                except Exception as exc:  # noqa: BLE001
                    warnings.warn(
                        f"Enrichment failed for finding {finding.id!r}: {exc}",
                        stacklevel=2,
                    )

        return enriched_count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_api(self, client: object, finding: FindingBead) -> dict[str, object]:
        """Send a single finding to the LLM and return parsed enrichment data.

        Args:
            client: An initialised ``anthropic.Anthropic`` client instance.
            finding: The finding to enrich.

        Returns:
            Dict with keys ``reasoning_extended``, ``remediation_sketch``,
            and ``enrichment_cost_usd``.
        """
        # The type is ``anthropic.Anthropic`` at runtime; kept as ``object``
        # in the signature so the module stays importable without the SDK.
        response = client.messages.create(  # type: ignore[union-attr]
            model=self._model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_message(finding)}],
        )
        raw_text: str = response.content[0].text
        parsed = _parse_enrichment_response(raw_text)
        cost = _calculate_cost(
            model=self._model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )
        return {
            "reasoning_extended": parsed["reasoning_extended"],
            "remediation_sketch": parsed["remediation_sketch"],
            "enrichment_cost_usd": cost,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _parse_enrichment_response(text: str) -> dict[str, str]:
    """Extract ``reasoning_extended`` and ``remediation_sketch`` from LLM output.

    Strips markdown code fences when present, then parses the remaining text
    as JSON.  If parsing fails the raw text is used as ``reasoning_extended``
    and ``remediation_sketch`` is left empty — ensuring we never silently
    discard content the model returned.

    Args:
        text: Raw text returned by the LLM.

    Returns:
        Dict with string values for ``reasoning_extended`` and
        ``remediation_sketch``.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Drop opening fence line (e.g. ```json) and closing ``` if present.
        inner_lines = lines[1:]
        if inner_lines and inner_lines[-1].strip() == "```":
            inner_lines = inner_lines[:-1]
        stripped = "\n".join(inner_lines)

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        # The model did not return valid JSON; preserve the raw text.
        return {"reasoning_extended": stripped, "remediation_sketch": ""}

    return {
        "reasoning_extended": str(data.get("reasoning_extended", "")),
        "remediation_sketch": str(data.get("remediation_sketch", "")),
    }


def _calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate the USD cost of an API call based on token counts.

    Uses per-model pricing tables when available; falls back to haiku-4-5
    pricing for unknown models.

    Args:
        model: The Anthropic model identifier used for the call.
        input_tokens: Number of input tokens consumed.
        output_tokens: Number of output tokens generated.

    Returns:
        Estimated cost in USD.
    """
    input_rate = _INPUT_COST_PER_TOKEN.get(model, _FALLBACK_INPUT_COST)
    output_rate = _OUTPUT_COST_PER_TOKEN.get(model, _FALLBACK_OUTPUT_COST)
    return input_tokens * input_rate + output_tokens * output_rate
