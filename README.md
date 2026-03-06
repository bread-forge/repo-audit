# repo-audit

Collect and analyze repository artifacts to surface documentation gaps, dead code, broken entry points, and untested goals.

## What it does

`repo-audit` reads a local repository directory without executing any of its code. It harvests documentation artifacts (README, CLAUDE.md, specs, docstrings, entry points) and performs static import-graph analysis. A four-layer comparator then detects gaps between adjacent representations (declared → structural → behavioral → activated), and the verdict module scores each gap into a `FindingBead` with severity, staleness class, and confidence. Findings are persisted locally under `~/.repo-audit/`.

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

# Run the full pipeline: collect, analyze, compare, score, and persist findings
repo-audit run /path/to/repo

# Run and only persist findings at or above a severity threshold
repo-audit run /path/to/repo --min-severity high

# List persisted findings for a repo
repo-audit list /path/to/repo

# List only high-severity findings added after a given cycle
repo-audit list /path/to/repo --min-severity high --since 20240101T120000Z
```

The `run` command writes raw JSON to `~/.repo-audit/cache/<owner>/<repo>/` and persists structured findings to `~/.repo-audit/beads/<owner>/<repo>/` via `RepoAuditStore`. The repo slug is derived from the `origin` git remote; repositories without a remote use `local/<dirname>`.

The `list` command reads from the bead store and prints a table of findings. Pass `--since <cycle-id>` for delta mode — only findings from audit cycles after that ID are shown.

## Modules

| File | Description |
|------|-------------|
| `src/repo_audit/cli.py` | Typer CLI: `collect`, `analyze`, `run`, and `list` commands |
| `src/repo_audit/collector/harvester.py` | `harvest()` — reads docs, docstrings, and entry points |
| `src/repo_audit/collector/artifacts.py` | `CollectedArtifacts` dataclass |
| `src/repo_audit/analyzer/__init__.py` | `analyze()` — entry point for import-graph analysis |
| `src/repo_audit/analyzer/ast_walker.py` | Discovers `.py` files and extracts imports via AST |
| `src/repo_audit/analyzer/import_graph.py` | Builds module → imports mapping |
| `src/repo_audit/analyzer/reachability.py` | BFS reachability from entry points |
| `src/repo_audit/analyzer/result.py` | `AnalysisResult` dataclass |
| `src/repo_audit/comparator/__init__.py` | `compare()` — runs all four gap layers, returns `GapSignal` list |
| `src/repo_audit/comparator/gap_signal.py` | `GapSignal` dataclass (layer, kind, subject, evidence) |
| `src/repo_audit/comparator/layers.py` | Four diff functions: declared_vs_structural, structural_vs_behavioral, behavioral_vs_activated, test_vs_declared |
| `src/repo_audit/verdict/__init__.py` | `verdict()` — converts `GapSignal` list into `FindingBead` list |
| `src/repo_audit/verdict/finding_bead.py` | `FindingBead` dataclass (id, severity, staleness_class, confidence, reasoning) |
| `src/repo_audit/verdict/scorer.py` | `score_signal()` — heuristic tables mapping layer/kind to severity and staleness |
| `src/repo_audit/store/bead_store.py` | `RepoAuditStore` — atomic JSON persistence for artifacts, analysis, and findings |

## Gap layers

The comparator runs four layers in order:

1. **declared vs structural** — modules with no module-level docstring (`undocumented_module`, severity: low)
2. **structural vs behavioral** — modules unreachable from any entry point (`unreachable_module`, severity: medium)
3. **behavioral vs activated** — CLI entry points whose target module is missing from the import graph (`broken_entry_point`, severity: critical)
4. **test vs declared** — spec Goals/Validation bullet items with no test-module coverage (`untested_goal`, severity: high)

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
