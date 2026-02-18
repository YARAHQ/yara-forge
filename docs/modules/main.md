# Module: main/

Core processing modules for rule collection, standardization, and output generation.

## Files

| File | Lines | Purpose |
| ---- | ----- | ------- |
| `rule_collector.py` | ~180 | Repository cloning, rule extraction |
| `rule_processors.py` | ~860 | Standardization, scoring, metadata |
| `rule_output.py` | ~350 | Package generation |
| `other_evals.py` | ~75 | Performance testing utilities |

## rule_collector.py

### Purpose

Clones YARA rule repositories from GitHub, extracts license files, finds all `.yar`/`.yara` files, and parses them using plyara.

### Entry Point

```python
def retrieve_yara_rule_sets(repo_staging_dir: str, yara_repos: list) -> list
```

**Input:** Staging directory path, list of repository configs from YAML

**Output:** List of repository sets with parsed rules

### Key Functions

| Function | Purpose |
| -------- | ------- |
| `retrieve_yara_rule_sets()` | Main entry: clone repos, find files, parse rules |
| `process_yara_file()` | Parse single YARA file via plyara |

### Behavior

- Uses GitPython for repository operations
- Supports sparse checkout for repositories with `path` config
- Skips Git LFS smudge (avoids large binary downloads)
- Extracts license from repository root
- Stores commit hash for reproducibility
- Handles UTF-8 encoding and parse errors gracefully

### Configuration Surface

From `yara-forge-config.yml`:

- `repo_staging_dir`: Local directory for cloned repos
- `yara_repositories[].url`: GitHub repository URL
- `yara_repositories[].branch`: Git branch to clone
- `yara_repositories[].path`: Optional subdirectory filter
- `yara_repositories[].recursive`: Whether to search subdirectories

### Touch Points

- **Depends on:** plyara (parsing), GitPython (git ops), config
- **Called by:** `yara-forge.py` (pipeline stage 1)
- **Outputs to:** In-memory rule sets passed to `rule_processors`

---

## rule_processors.py

### Purpose

The core standardization module. Transforms raw parsed rules into standardized, scored, deduplicated rules with consistent metadata.

### Entry Point

```python
def process_yara_rules(yara_rule_repo_sets: list, YARA_FORGE_CONFIG: dict) -> list
```

**Input:** Repository sets from collector, configuration dict

**Output:** Processed repository sets with enriched rules

### Key Functions

| Function | Purpose |
| -------- | ------- |
| `process_yara_rules()` | Main orchestrator for all processing |
| `align_yara_rule_name()` | Prefix rule name with repo identifier |
| `align_yara_rule_description()` | Standardize description field |
| `align_yara_rule_author()` | Normalize author from various keys |
| `align_yara_rule_date()` | Extract date from git history |
| `align_yara_rule_hashes()` | Normalize hash field names |
| `align_yara_rule_reference()` | Add source URL reference |
| `align_yara_rule_uuid()` | Generate deterministic UUIDv5 |
| `add_tags_to_rule()` | Extract and normalize tags |
| `evaluate_yara_rule_score()` | Calculate rule score |
| `retrieve_custom_importance_score()` | Load custom scoring |
| `check_rule_uses_private_rules()` | Detect private rule deps |
| `adjust_identifier_names()` | Rewrite condition references |
| `sort_meta_data_values()` | Order metadata per config |
| `modify_meta_data_value()` | Add/update metadata entry |
| `modify_yara_rule_quality()` | Adjust quality score |

### Deduplication

Uses plyara's `generate_hash()` to create a logic hash of rule conditions. Rules with identical logic hashes are deduplicated (first occurrence wins). Private rules are excluded from deduplication.

### Scoring System

1. Start with repository's base `quality` score
2. Check for custom importance score in `yara-forge-custom-scoring.yml`
3. Analyze metadata keywords (suspicious, hunting, experimental)
4. Apply reductions for hunting/untested rules
5. Special case: ELF module rules capped at 40

### Private Rule Handling

- Detects private rules via `scopes` containing `'private'`
- Tracks which public rules depend on which private rules
- Rewrites condition references when private rules are renamed
- Maintains mapping for output stage

### Configuration Surface

From `yara-forge-config.yml`:

- `rule_base_score`: Default score (75)
- `meta_data_order`: Metadata field ordering

From `yara-forge-custom-scoring.yml`:

- `importance-scores`: Per-rule importance overrides

### Touch Points

- **Depends on:** plyara, dateparser, git (via commit history), config files
- **Called by:** `yara-forge.py` (pipeline stage 2)
- **Outputs to:** In-memory processed rules passed to `rule_qa`

---

## rule_output.py

### Purpose

Generates the final `.yar` package files from processed and quality-checked rules.

### Entry Point

```python
def write_yara_packages(
    processed_yara_repos: list,
    program_version: str,
    yaraqa_commit: str,
    YARA_FORGE_CONFIG: dict
) -> list
```

**Input:** Evaluated repository sets, version info, config

**Output:** List of generated file paths, writes packages to disk

### Key Functions

| Function | Purpose |
| -------- | ------- |
| `write_yara_packages()` | Main package generation |
| `write_build_stats()` | Generate build_stats.md |
| `_normalize_datetime()` | Internal date normalization |

### Package Filtering

For each configured package, rules are filtered by:

- `minimum_quality`: Quality score threshold
- `minimum_score`: Rule score threshold
- `minimum_age` / `maximum_age`: Rule age range in days
- `force_include_importance_level`: Override to include important rules
- `force_exclude_importance_level`: Override to exclude low-importance

### Output Format

Each package file contains:

1. YARA module imports (pe, elf, hash, dotnet)
2. Package header comment with metadata and thresholds
3. Per-repository sections with commit info and license
4. Rules organized by source repository
5. Private rules prepended before dependent public rules

### Configuration Surface

From `yara-forge-config.yml`:

- `yara_rule_packages`: Package definitions (core, extended, full)
- `rule_set_header`: Template for package headers

### Touch Points

- **Depends on:** Config, processed rule data
- **Called by:** `yara-forge.py` (pipeline stage 4)
- **Outputs to:** `packages/*/yara-rules-*.yar`, `build_stats.md`

---

## other_evals.py

### Purpose

Performance testing utilities for regex benchmarking.

### Key Class

```python
class PerformanceTimer:
    def __init__()
    def baseline_measurements() -> None
    def test_regex_performance(regex: str, iterations: int = 5) -> bool
```

### Behavior

- Loads test data (ReactOS strings extract)
- Runs baseline measurements with known good/bad patterns
- Provides threshold-based regex performance testing
- Used by yaraQA for performance evaluation

### Touch Points

- **Depends on:** Test data file (ReactOS strings)
- **Called by:** `qa/yaraQA/` submodule
