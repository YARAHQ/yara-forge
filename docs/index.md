# YARA Forge — Project Map (IKL)

This document helps you navigate the codebase quickly. Use it to find where to make changes.

## Directory Overview

```
yara-forge/
├── yara-forge.py           # CLI entry point, pipeline orchestration
├── main/                   # Core processing modules
│   ├── rule_collector.py   # Repository cloning, rule extraction
│   ├── rule_processors.py  # Standardization, scoring, metadata
│   └── rule_output.py      # Package generation (.yar files)
├── qa/                     # Quality assurance
│   ├── rule_qa.py          # QA checks, issue tracking
│   └── yaraQA/             # Git submodule for advanced analysis
├── packages/               # Output: generated rule packages
│   ├── core/               # High-quality rules (score >= 65)
│   ├── extended/           # Medium-quality rules (score >= 60)
│   └── full/               # All rules (score >= 40)
├── repos/                  # Git staging: cloned source repositories
├── tests/                  # Unit tests (pytest)
├── docs/                   # Documentation
└── .github/workflows/      # CI/CD automation
```

## Documentation Links

| Document | Purpose |
| -------- | ------- |
| [architecture.md](./architecture.md) | System design, data flows, component interactions |
| [modules/cli.md](./modules/cli.md) | CLI entry point (`yara-forge.py`) |
| [modules/main.md](./modules/main.md) | Core processing modules (`main/`) |
| [modules/qa.md](./modules/qa.md) | Quality assurance (`qa/`) |
| [decisions.md](./decisions.md) | Design decisions and rationale |
| [glossary.md](./glossary.md) | Project-specific terms |
| [code-structure.md](./code-structure.md) | API reference (functions, classes) |

## Configuration Files

| File | Purpose |
| ---- | ------- |
| `yara-forge-config.yml` | Main config: repositories, thresholds, package definitions |
| `yara-forge-custom-scoring.yml` | Per-rule importance scores and noisy-rule penalties |
| `requirements.txt` | Python dependencies |

## How to Find Things Fast

### Common Tasks → Where to Look

| Task | Start Here |
| ---- | ---------- |
| Add a new YARA repository | `yara-forge-config.yml` → `yara_repositories` section |
| Change package thresholds | `yara-forge-config.yml` → `yara_rule_packages` section |
| Adjust rule importance/scoring | `yara-forge-custom-scoring.yml` |
| Modify metadata standardization | `main/rule_processors.py` → `align_yara_rule_*` functions |
| Change QA severity levels | `yara-forge-config.yml` → `issue_levels` |
| Add new QA checks | `qa/rule_qa.py` or `qa/yaraQA/` submodule |
| Change output format | `main/rule_output.py` → `write_yara_packages()` |
| Debug rule collection | `main/rule_collector.py` → `retrieve_yara_rule_sets()` |
| Run/modify tests | `tests/` directory |
| Change CI/CD behavior | `.github/workflows/` |

### Key Symbols to Search

| Symbol | Location | Purpose |
| ------ | -------- | ------- |
| `retrieve_yara_rule_sets` | `main/rule_collector.py` | Entry point for repository collection |
| `process_yara_rules` | `main/rule_processors.py` | Entry point for rule standardization |
| `evaluate_rules_quality` | `qa/rule_qa.py` | Entry point for QA checks |
| `write_yara_packages` | `main/rule_output.py` | Entry point for package generation |
| `align_yara_rule_*` | `main/rule_processors.py` | Metadata normalization functions |
| `check_issues_critical` | `qa/rule_qa.py` | Critical syntax validation |
| `YARA_FORGE_CONFIG` | Passed throughout | Main configuration dictionary |

### Search Keywords

- **Scoring/quality:** `score`, `quality`, `importance`, `reduction`
- **Metadata:** `meta_data`, `align_yara_rule`, `modify_meta_data_value`
- **Deduplication:** `logic_hash`, `generate_hash`, `duplicate`
- **Private rules:** `private`, `private_rules_used`, `adjust_identifier_names`
- **Tags:** `add_tags_to_rule`, `tags`, `FILE`
- **Output:** `write_yara_packages`, `rule_set_header`, `packages/`

## Pipeline Stages (Quick Reference)

```
1. COLLECT    →  rule_collector.retrieve_yara_rule_sets()
2. PROCESS    →  rule_processors.process_yara_rules()
3. QA         →  rule_qa.evaluate_rules_quality()
4. OUTPUT     →  rule_output.write_yara_packages()
5. VALIDATE   →  rule_qa.check_yara_packages()
```

## Output Artifacts

| File | Description |
| ---- | ----------- |
| `packages/*/yara-rules-*.yar` | Generated rule packages |
| `yara-forge.log` | Detailed execution log |
| `yara-forge-rule-issues.yml` | QA findings per rule |
| `build_stats.md` | Build statistics for releases |
