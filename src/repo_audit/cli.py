"""repo-audit CLI — collect, analyze, compare, and persist repository audit data."""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import typer

from repo_audit.analyzer import analyze as _analyze
from repo_audit.collector import harvest as _harvest
from repo_audit.comparator import compare as _compare
from repo_audit.enricher.enricher import DEFAULT_MODEL, Enricher
from repo_audit.store import RepoAuditStore
from repo_audit.verdict import verdict as _verdict

app = typer.Typer(
    name="repo-audit",
    help="Audit a repository: collect artifacts and analyze its import structure.",
    no_args_is_help=True,
)

CACHE_DIR = Path.home() / ".repo-audit" / "cache"

# Severity ordering — must stay in sync with bead_store._SEVERITY_RANK.
_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_VALID_SEVERITIES = ("low", "medium", "high", "critical")

# Column widths for the findings table.
_COL_ID = 16
_COL_SEVERITY = 8
_COL_STALENESS = 20


def _derive_repo_slug(repo_path: Path) -> str:
    """Derive an owner/repo slug from the git remote origin URL.

    Falls back to ``local/<dirname>`` when the directory is not a git
    repository or has no origin remote.
    """
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        url = result.stdout.strip()
        # Normalize: strip trailing .git
        if url.endswith(".git"):
            url = url[:-4]
        # SSH form: git@github.com:owner/repo
        if url.startswith("git@"):
            owner_repo = url.split(":", 1)[1]
        else:
            # HTTPS form: https://github.com/owner/repo
            parts = url.rstrip("/").split("/")
            owner_repo = "/".join(parts[-2:])
        if "/" in owner_repo:
            return owner_repo
    except (subprocess.CalledProcessError, IndexError, ValueError):
        pass
    return f"local/{repo_path.name}"


def _to_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


def _write_output(text: str, output: Optional[Path]) -> None:
    """Print *text* to stdout, or write it to *output* if provided."""
    if output is None:
        typer.echo(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Written to {output}")


def _validate_repo_path(repo_path: Path) -> Path:
    """Resolve and validate that *repo_path* is an existing directory."""
    resolved = repo_path.resolve()
    if not resolved.is_dir():
        typer.echo(f"Error: {repo_path} is not a directory.", err=True)
        raise typer.Exit(code=1)
    return resolved


def _validate_severity(value: str) -> None:
    """Exit with code 1 if *value* is not a recognised severity level."""
    if value not in _VALID_SEVERITIES:
        typer.echo(
            f"Error: --min-severity must be one of {_VALID_SEVERITIES}, got {value!r}.",
            err=True,
        )
        raise typer.Exit(code=1)


def _new_cycle_id() -> str:
    """Generate a sortable UTC cycle identifier (e.g. ``20240101T120000Z``)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _severity_passes(severity: str, min_severity: str) -> bool:
    """Return True when *severity* is at or above *min_severity*."""
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(min_severity, 0)


def _should_enrich(enrich: Optional[bool]) -> bool:
    """Determine whether enrichment should run.

    Explicit flags take priority.  When neither ``--enrich`` nor
    ``--no-enrich`` is supplied, auto-detect by checking whether
    ``ANTHROPIC_API_KEY`` is present in the environment.
    """
    if enrich is not None:
        return enrich
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _print_findings_table(findings: list) -> None:
    """Print *findings* as an aligned table to stdout.

    Extended enrichment fields (``reasoning_extended``, ``remediation_sketch``)
    are printed as indented lines below each finding when present.
    """
    header = (
        f"{'ID':<{_COL_ID}}  "
        f"{'SEVERITY':<{_COL_SEVERITY}}  "
        f"{'STALENESS CLASS':<{_COL_STALENESS}}  "
        f"SUMMARY"
    )
    typer.echo(header)
    typer.echo("-" * len(header))
    for f in findings:
        typer.echo(
            f"{f.id:<{_COL_ID}}  "
            f"{f.severity:<{_COL_SEVERITY}}  "
            f"{f.staleness_class:<{_COL_STALENESS}}  "
            f"{f.summary}"
        )
        if f.reasoning_extended:
            typer.echo(f"  Reasoning:    {f.reasoning_extended}")
        if f.remediation_sketch:
            typer.echo(f"  Remediation:  {f.remediation_sketch}")


@app.command()
def collect(
    repo_path: Path = typer.Argument(..., help="Path to the repository root."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write JSON to this file instead of stdout."
    ),
) -> None:
    """Collect repository artifacts (README, docs, docstrings, entry points)."""
    resolved = _validate_repo_path(repo_path)
    artifacts = _harvest(resolved)
    _write_output(_to_json(dataclasses.asdict(artifacts)), output)


@app.command()
def analyze(
    repo_path: Path = typer.Argument(..., help="Path to the repository root."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write JSON to this file instead of stdout."
    ),
) -> None:
    """Analyze the Python import graph of a repository."""
    resolved = _validate_repo_path(repo_path)
    result = _analyze(resolved)
    _write_output(_to_json(dataclasses.asdict(result)), output)


@app.command()
def run(
    repo_path: Path = typer.Argument(..., help="Path to the repository root."),
    min_severity: str = typer.Option(
        "low",
        "--min-severity",
        help="Minimum severity level to persist (low/medium/high/critical).",
    ),
    print_cycle_id: bool = typer.Option(
        False,
        "--print-cycle-id/--no-print-cycle-id",
        help="Print the audit cycle ID to stdout after run.",
    ),
    enrich: Optional[bool] = typer.Option(
        None,
        "--enrich/--no-enrich",
        help=(
            "Enrich findings with LLM-generated reasoning and remediation sketches. "
            "Defaults to auto-detect: enabled when ANTHROPIC_API_KEY is set."
        ),
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model",
        help="Anthropic model ID used for enrichment.",
    ),
    re_enrich: bool = typer.Option(
        False,
        "--re-enrich/--no-re-enrich",
        help="Re-enrich findings that have already been enriched in a previous run.",
    ),
) -> None:
    """Collect, analyze, compare, and persist findings to the audit store."""
    _validate_severity(min_severity)
    resolved = _validate_repo_path(repo_path)
    slug = _derive_repo_slug(resolved)
    cycle_id = _new_cycle_id()

    typer.echo(f"Auditing {slug} ...")

    artifacts = _harvest(resolved)
    result = _analyze(resolved)

    # Write raw JSON to the cache directory for easy inspection
    cache_dir = CACHE_DIR / slug
    cache_dir.mkdir(parents=True, exist_ok=True)
    artifacts_path = cache_dir / "artifacts.json"
    analysis_path = cache_dir / "analysis.json"
    artifacts_path.write_text(_to_json(dataclasses.asdict(artifacts)), encoding="utf-8")
    analysis_path.write_text(_to_json(dataclasses.asdict(result)), encoding="utf-8")

    # Compare layers and produce scored findings
    signals = _compare(artifacts, result)
    findings = _verdict(signals, cycle_id=cycle_id, repo_path=str(resolved))

    # Persist via RepoAuditStore
    store = RepoAuditStore()
    store.save_artifacts(slug, artifacts)
    store.save_analysis(slug, result)

    saved_count = 0
    for finding in findings:
        if _severity_passes(finding.severity, min_severity):
            store.save_finding(slug, finding)
            saved_count += 1

    typer.echo(f"Artifacts: {artifacts_path}")
    typer.echo(f"Analysis:  {analysis_path}")
    typer.echo(f"Persisted to store under {slug}.")
    typer.echo(f"Findings:  {saved_count} persisted (min-severity={min_severity}).")

    if print_cycle_id:
        typer.echo(f"Cycle ID:  {cycle_id}")

    if _should_enrich(enrich):
        if re_enrich:
            # Clear existing enrichment so the enricher re-processes all findings.
            for stored_finding in store.list_findings(slug):
                if stored_finding.reasoning_extended is not None:
                    store.patch_finding(
                        slug,
                        stored_finding.id,
                        reasoning_extended=None,
                        remediation_sketch=None,
                        enrichment_cost_usd=None,
                    )

        enricher = Enricher(store=store, model=model)
        enriched_count = enricher.enrich(slug)
        typer.echo(f"Enriched:  {enriched_count} findings.")


@app.command("list")
def list_findings(
    repo_path: Path = typer.Argument(..., help="Path to the repository root."),
    min_severity: str = typer.Option(
        "low",
        "--min-severity",
        help="Minimum severity level to show (low/medium/high/critical).",
    ),
    since: Optional[str] = typer.Option(
        None,
        "--since",
        help="Show only findings with cycle_id strictly greater than this value (delta mode).",
    ),
) -> None:
    """List findings from the audit store for a repository."""
    _validate_severity(min_severity)
    resolved = _validate_repo_path(repo_path)
    slug = _derive_repo_slug(resolved)

    store = RepoAuditStore()
    findings = store.list_findings(slug, min_severity=min_severity, since_cycle_id=since)

    if not findings:
        typer.echo("No findings.")
        return

    _print_findings_table(findings)
