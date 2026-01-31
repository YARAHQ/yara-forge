# YARA Forge — Architecture

## Overview

YARA Forge is a batch processing pipeline that transforms YARA rules from multiple source repositories into standardized, quality-checked rule packages.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  45+ GitHub     │     │                  │     │   Rule Packages │
│  Repositories   │────▶│   YARA Forge     │────▶│   (core/ext/    │
│  (YARA rules)   │     │   Pipeline       │     │    full .yar)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │  QA Reports  │
                        │  Build Stats │
                        └──────────────┘
```

## Major Components

### 1. CLI Orchestrator (`yara-forge.py`)

The entry point that:

- Parses command-line arguments (`--debug`, `-c`)
- Configures logging (console + file)
- Loads configuration from YAML
- Executes pipeline stages in sequence
- Reports status via section headers

### 2. Rule Collector (`main/rule_collector.py`)

Responsible for:

- Cloning/updating Git repositories
- Sparse checkout for repositories with path filters
- Extracting license files
- Finding all `.yar`/`.yara` files
- Parsing rules via plyara library

### 3. Rule Processors (`main/rule_processors.py`)

The largest module, handling:

- Logic-hash deduplication across repositories
- Metadata standardization (author, date, description, hashes)
- Rule name prefixing with repository identifier
- UUID generation for tracking
- Tag extraction and normalization
- Score evaluation and importance assignment
- Private rule dependency management

### 4. Quality Assurance (`qa/rule_qa.py` + `qa/yaraQA/`)

Performs:

- Syntax validation (compile test)
- Critical issue detection (Level 4 → rule rejected)
- Efficiency analysis via yaraQA submodule
- Performance benchmarking
- Quality score adjustments
- Issue reporting to YAML

### 5. Rule Output (`main/rule_output.py`)

Generates:

- Filtered rule packages based on thresholds
- Private rule inclusion for dependencies
- Package headers with metadata
- Build statistics for releases

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CONFIGURATION                                 │
│  yara-forge-config.yml    yara-forge-custom-scoring.yml             │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 1: COLLECT                                                     │
│ rule_collector.retrieve_yara_rule_sets()                            │
│                                                                      │
│ Input:  Config (repository URLs, paths, branches)                   │
│ Output: yara_rule_repo_sets[]                                       │
│         [{name, url, author, quality, license, commit,              │
│           rules_sets: [{file_path, rules: [parsed_rule]}]}]         │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 2: PROCESS                                                     │
│ rule_processors.process_yara_rules()                                │
│                                                                      │
│ Transformations:                                                     │
│ - Deduplicate by logic hash                                         │
│ - Prefix rule names with repo identifier                            │
│ - Normalize metadata fields                                         │
│ - Generate UUIDs                                                    │
│ - Extract and normalize tags                                        │
│ - Calculate scores and importance                                   │
│ - Track private rule dependencies                                   │
│                                                                      │
│ Output: processed_yara_repos[] (same structure, enriched rules)     │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 3: QA                                                          │
│ rule_qa.evaluate_rules_quality()                                    │
│                                                                      │
│ Checks:                                                              │
│ - Critical syntax issues (Level 4 → reject rule)                    │
│ - Syntax warnings (Level 2-3 → reduce score)                        │
│ - yaraQA efficiency analysis                                        │
│ - Custom quality reductions (noisy-rules config)                    │
│                                                                      │
│ Side effects:                                                        │
│ - Updates rule quality scores                                       │
│ - Writes yara-forge-rule-issues.yml                                 │
│                                                                      │
│ Output: evaluated_yara_repos[] (quality-filtered)                   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 4: OUTPUT                                                      │
│ rule_output.write_yara_packages()                                   │
│                                                                      │
│ For each package (core, extended, full):                            │
│ - Filter by: minimum_quality, minimum_score, age range             │
│ - Apply importance overrides (force include/exclude)                │
│ - Collect required private rules                                    │
│ - Generate .yar file with headers                                   │
│ - Track statistics                                                  │
│                                                                      │
│ Output:                                                              │
│ - packages/core/yara-rules-core.yar                                 │
│ - packages/extended/yara-rules-extended.yar                         │
│ - packages/full/yara-rules-full.yar                                 │
│ - build_stats.md                                                    │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 5: VALIDATE                                                    │
│ rule_qa.check_yara_packages()                                       │
│                                                                      │
│ - Compile each generated package with YARA engine                   │
│ - Exit 0 on success, 1 on failure                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Data Structures

### Rule (plyara format)

```python
{
    'rule_name': str,
    'metadata': [{'key': value}, ...],
    'strings': [...],
    'condition_terms': [...],
    'raw_condition': str,
    'scopes': ['private', ...],  # optional
    # Added by YARA Forge:
    'logic_hash': str,
    'original_rule_name': str,
    'private_rules_used': [str, ...],
}
```

### Repository Set

```python
{
    'name': str,           # e.g., "signature-base"
    'url': str,            # GitHub URL
    'author': str,
    'quality': int,        # Base quality score (70-90)
    'license': str,        # License text
    'commit': str,         # Git commit hash
    'rules_sets': [
        {
            'file_path': str,
            'rules': [rule, ...]
        }
    ]
}
```

## External Dependencies

### Internal

| Dependency | Usage |
| ---------- | ----- |
| plyara | YARA rule parsing and manipulation |
| yara-python | Rule compilation and validation |
| GitPython | Repository cloning and history |
| PyYAML | Configuration loading |
| dateparser | Flexible date parsing |
| pyre2 (fb-re2) | Regex performance analysis |

### External Services

| Service | Usage |
| ------- | ----- |
| GitHub | Source repositories (via Git clone) |

### Submodules

| Submodule | Location | Purpose |
| --------- | -------- | ------- |
| yaraQA | `qa/yaraQA/` | Advanced rule efficiency analysis |

## Boundaries

### Internal (This Project)

- Rule collection, processing, QA, output
- Configuration management
- Pipeline orchestration
- Build statistics

### External (Not This Project)

- Source YARA rule content (from external repos)
- yaraQA analysis logic (submodule)
- YARA engine compilation
- Git operations (GitPython wrapper)

## Package Tiers

| Package | Quality | Score | Age | Use Case |
| ------- | ------- | ----- | --- | -------- |
| core | >= 70 | >= 65 | 1-2500 days | Production, low FP tolerance |
| extended | >= 50 | >= 60 | 1-5000 days | Broader coverage, moderate FP |
| full | >= 20 | >= 40 | 0-10000 days | Research, threat hunting |

Importance levels can override these thresholds via `force_include_importance_level` and `force_exclude_importance_level` settings.
