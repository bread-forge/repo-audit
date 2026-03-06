# repo-audit

Collect and analyze repository artifacts to surface documentation gaps, dead code, broken entry points, untested goals, and security vulnerabilities.

## What it does

`repo-audit` reads a local repository directory without executing any of its code. It harvests documentation artifacts (README, CLAUDE.md, specs, docstrings, entry points) and performs static import-graph analysis. A four-layer comparator detects gaps between adjacent representations (declared → structural → behavioral → activated), and the verdict module scores each gap into a `FindingBead` with severity, staleness class, and confidence. Findings are persisted locally under `~/.repo-audit/`. Optionally, an enricher calls the Anthropic API to append extended reasoning and a remediation sketch to each finding. The `specgen` command then clusters related findings by shared blast-radius modules and writes kiln-format Markdown spec files — skipping clusters already covered by existing specs. A separate security pipeline wraps Trivy (CVE scanning), Gitleaks (secret detection), and an optional LLM threat-modelling agent, normalising all results into the same `FindingBead` store.

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

# Run with LLM enrichment explicitly enabled
repo-audit run /path/to/repo --enrich

# Run with enrichment disabled even when ANTHROPIC_API_KEY is set
repo-audit run /path/to/repo --no-enrich

# Re-enrich findings that were already enriched in a previous run
repo-audit run /path/to/repo --re-enrich

# Use a specific Anthropic model for enrichment
repo-audit run /path/to/repo --model claude-haiku-4-5-20251001

# Run the full pipeline and also run the security scan (Trivy + Gitleaks)
repo-audit run /path/to/repo --security

# Run the full pipeline with security scan and LLM threat modelling
repo-audit run /path/to/repo --security --llm-threat-model

# Run only the security scan (Trivy + Gitleaks), skipping the standard pipeline
repo-audit security-scan /path/to/repo

# Run security scan with LLM threat modelling
repo-audit security-scan /path/to/repo --llm-threat-model

# List persisted findings for a repo
repo-audit list /path/to/repo

# List only high-severity findings added after a given cycle
repo-audit list /path/to/repo --min-severity high --since 20240101T120000Z

# Generate kiln spec files from findings (writes to ./specs/ by default)
repo-audit specgen /path/to/repo

# Write specs to a custom directory
repo-audit specgen /path/to/repo --out-dir path/to/specs

# Preview the cluster plan without writing any files
repo-audit specgen /path/to/repo --dry-run

# Generate specs only for findings added after a given cycle
repo-audit specgen /path/to/repo --since 20240101T120000Z
```

The `run` command writes raw JSON to `~/.repo-audit/cache/<owner>/<repo>/` and persists structured findings to `~/.repo-audit/beads/<owner>/<repo>/` via `RepoAuditStore`. The repo slug is derived from the `origin` git remote; repositories without a remote use `local/<dirname>`.

The `list` command reads from the bead store and prints a table of findings, including any enrichment fields. Pass `--since <cycle-id>` for delta mode — only findings from audit cycles after that ID are shown.

The `specgen` command loads findings from the bead store, groups them into clusters of up to 5 related findings (connected by shared blast-radius modules), skips clusters already covered by existing spec files in the output directory, and writes one `spec-cluster-NNN.md` file per new cluster. Each file contains YAML front-matter (`source_findings`, `blast_radius`, `priority`, `depends_on`) followed by Overview, Goals, Modules, Validation, and Meta sections.

The `security-scan` command runs Trivy and Gitleaks against the repository and persists each finding to the same bead store used by the standard pipeline. Both scanners skip silently when the respective tool is not installed. Pass `--llm-threat-model` to additionally invoke `ThreatModelAgent`, which calls the Anthropic API to generate threat findings from the repository's README, CLAUDE.md, and entry points (requires `ANTHROPIC_API_KEY`).

### Enrichment auto-detection

When neither `--enrich` nor `--no-enrich` is supplied, the `run` command checks for the `ANTHROPIC_API_KEY` environment variable. Enrichment is enabled automatically when the key is present and skipped silently when it is not.

## Modules

| File | Description |
|------|-------------|
| `src/repo_audit/cli.py` | Typer CLI: `collect`, `analyze`, `run`, `list`, `specgen`, and `security-scan` commands |
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
| `src/repo_audit/verdict/finding_bead.py` | `FindingBead` dataclass — includes enrichment fields `reasoning_extended`, `remediation_sketch`, `enrichment_cost_usd` |
| `src/repo_audit/verdict/scorer.py` | `score_signal()` — heuristic tables mapping layer/kind to severity and staleness |
| `src/repo_audit/store/bead_store.py` | `RepoAuditStore` — atomic JSON persistence for artifacts, analysis, and findings; `patch_finding()` for in-place enrichment updates |
| `src/repo_audit/enricher/__init__.py` | Enricher package public exports |
| `src/repo_audit/enricher/enricher.py` | `Enricher` class — batches unenriched findings, calls the Anthropic Messages API, and patches the store |
| `src/repo_audit/enricher/prompts.py` | System prompt and `build_user_message()` for LLM enrichment calls |
| `src/repo_audit/security/__init__.py` | Security sub-package marker |
| `src/repo_audit/security/trivy.py` | `TrivyScanner` — wraps `trivy fs` to detect CVEs; normalises output into `FindingBead` records with `staleness_class='dependency'` |
| `src/repo_audit/security/gitleaks.py` | `GitleaksScanner` — wraps `gitleaks detect` to find exposed secrets; stores file location only, never the secret value |
| `src/repo_audit/security/threat_model.py` | `ThreatModelAgent` — calls the Anthropic API to identify security threats from README, CLAUDE.md, and entry points |
| `src/repo_audit/specgen/__init__.py` | SpecGen package public exports |
| `src/repo_audit/specgen/clusterer.py` | `cluster_findings()` — greedy union-find over module-overlap edges; produces deterministic clusters of ≤5 findings |
| `src/repo_audit/specgen/formatter.py` | `format_spec()` — renders a cluster to a kiln-format Markdown file with YAML front-matter |
| `src/repo_audit/specgen/dedup.py` | `load_covered_finding_ids()` and `filter_new_clusters()` — suppresses re-generation of already-covered clusters |

## Gap layers

The comparator runs four layers in order:

1. **declared vs structural** — modules with no module-level docstring (`undocumented_module`, severity: low)
2. **structural vs behavioral** — modules unreachable from any entry point (`unreachable_module`, severity: medium)
3. **behavioral vs activated** — CLI entry points whose target module is missing from the import graph (`broken_entry_point`, severity: critical)
4. **test vs declared** — spec Goals/Validation bullet items with no test-module coverage (`untested_goal`, severity: high)

## Security scanners

The security pipeline runs independently of the gap-layer pipeline and persists findings to the same bead store:

| Scanner | Tool | Finding severity | Staleness class |
|---------|------|-----------------|-----------------|
| `TrivyScanner` | `trivy fs` | Lowercased from Trivy's `Severity` field | `dependency` |
| `GitleaksScanner` | `gitleaks detect` | `critical` | `critical` |
| `ThreatModelAgent` | Anthropic API | LLM-assigned (critical/high/medium/low) | LLM-assigned |

All three scanners return an empty list — without raising — when their underlying tool or API key is unavailable.

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
- [`anthropic`](https://pypi.org/project/anthropic/) — Anthropic Python SDK, used by the enricher and `ThreatModelAgent` for LLM-powered analysis
