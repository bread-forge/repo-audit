# repo-audit

Collect and analyze repository artifacts to audit structure, documentation, and import graphs.

## What it does

`repo-audit` reads a local repository directory without executing any of its code. It
harvests documentation artifacts (README, CLAUDE.md, specs, docstrings, entry points) and
performs static import-graph analysis to identify reachable modules. Results are persisted
locally under `~/.repo-audit/`.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

This installs the `repo-audit` CLI and all dependencies into a local virtual environment.

## Usage

```sh
# Collect artifacts and print JSON to stdout
repo-audit collect /path/to/repo

# Collect and write to a file
repo-audit collect /path/to/repo --output artifacts.json

# Analyze import graph
repo-audit analyze /path/to/repo

# Run collect + analyze, cache results, and persist to the audit store
repo-audit run /path/to/repo
```

The `run` command writes JSON files to `~/.repo-audit/cache/<owner>/<repo>/` and persists
structured data to `~/.repo-audit/beads/<owner>/<repo>/` via `RepoAuditStore`. The repo
slug is derived from the `origin` git remote; repositories without a remote use `local/<dirname>`.

## Modules

| File | Description |
|------|-------------|
| `src/repo_audit/cli.py` | Typer CLI: `collect`, `analyze`, and `run` commands |
| `src/repo_audit/collector/harvester.py` | `harvest()` — reads docs, docstrings, and entry points |
| `src/repo_audit/collector/artifacts.py` | `CollectedArtifacts` dataclass |
| `src/repo_audit/analyzer/__init__.py` | `analyze()` — entry point for import-graph analysis |
| `src/repo_audit/analyzer/ast_walker.py` | Discovers `.py` files and extracts imports via AST |
| `src/repo_audit/analyzer/import_graph.py` | Builds module → imports mapping |
| `src/repo_audit/analyzer/reachability.py` | BFS reachability from entry points |
| `src/repo_audit/analyzer/result.py` | `AnalysisResult` dataclass |
| `src/repo_audit/store/bead_store.py` | `RepoAuditStore` — atomic JSON persistence via BeadStore |

## Tests

```sh
uv run pytest
```

Lint:

```sh
uv run ruff check
```

## Dependencies

- [`typer`](https://typer.tiangolo.com/) — CLI framework
- [`beads`](https://pypi.org/project/beads/) — bead store persistence (transitive, via `store` module)
