"""repo-audit CLI — collect, analyze, and persist repository audit data."""

from __future__ import annotations

import dataclasses
import json
import subprocess
from pathlib import Path
from typing import Optional

import typer

from repo_audit.analyzer import analyze as _analyze
from repo_audit.collector import harvest as _harvest
from repo_audit.store import RepoAuditStore

app = typer.Typer(
    name="repo-audit",
    help="Audit a repository: collect artifacts and analyze its import structure.",
    no_args_is_help=True,
)

CACHE_DIR = Path.home() / ".repo-audit" / "cache"


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
) -> None:
    """Collect and analyze a repository, then persist results to the audit store."""
    resolved = _validate_repo_path(repo_path)
    slug = _derive_repo_slug(resolved)

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

    # Persist via RepoAuditStore
    store = RepoAuditStore()
    store.save_artifacts(slug, artifacts)
    store.save_analysis(slug, result)

    typer.echo(f"Artifacts: {artifacts_path}")
    typer.echo(f"Analysis:  {analysis_path}")
    typer.echo(f"Persisted to store under {slug}.")
