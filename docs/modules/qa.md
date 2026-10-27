# Module: qa/

Quality assurance and rule validation.

## Files

| File | Lines | Purpose |
| ---- | ----- | ------- |
| `rule_qa.py` | ~370 | QA checks, issue tracking, validation |
| `yaraQA/` | submodule | Advanced rule efficiency analysis |

## rule_qa.py

### Purpose

Performs multi-level quality checks on processed rules, adjusts quality scores based on issues found, and validates final output packages.

### Entry Points

```python
def evaluate_rules_quality(processed_yara_repos: list, config: dict) -> list
def check_yara_packages(repo_files: list) -> int
```

### Key Functions

| Function | Purpose |
| -------- | ------- |
| `evaluate_rules_quality()` | Main QA orchestrator |
| `check_issues_critical()` | Level 4: compilation failures (reject rule) |
| `check_syntax_issues()` | Level 2-3: compilation warnings |
| `retrieve_custom_quality_reduction()` | Load noisy-rule penalties |
| `retrieve_custom_score()` | Load custom score overrides |
| `write_issues_to_file()` | Output issues to YAML |
| `check_yara_packages()` | Final package validation |
| `get_yara_qa_commit_hash()` | Get yaraQA submodule version |
| `modify_yara_rule_quality()` | Adjust quality score |
| `modify_meta_data_value()` | Update metadata |

### Issue Severity Levels

| Level | Impact | Score Adjustment | Outcome |
| ----- | ------ | ---------------- | ------- |
| 1 | Cosmetic | -2 | Rule included |
| 2 | Minor performance | -25 | Rule included |
| 3 | Major performance/logic | -70 | Rule likely filtered |
| 4 | Critical (broken) | -1000 | Rule excluded |

### QA Pipeline

1. **Critical Syntax Check** (`check_issues_critical`)
   - Attempts YARA compilation
   - Rules that fail are marked Level 4 and excluded
   - Includes private rule dependencies for compilation

2. **Syntax Issue Detection** (`check_syntax_issues`)
   - Detects compilation warnings
   - Assigns Level 2-3 based on severity

3. **yaraQA Analysis** (via submodule)
   - Efficiency checks on string patterns
   - Condition logic validation
   - Performance benchmarking

4. **Custom Quality Reductions**
   - Applies penalties from `noisy-rules` in custom-scoring.yml
   - Supports prefix matching for rule families

5. **Issue Logging**
   - All issues written to `yara-forge-rule-issues.yml`
   - Grouped by repository with recommendations

### Configuration Surface

From `yara-forge-config.yml`:

- `issue_levels`: Mapping of severity to score reduction

From `yara-forge-custom-scoring.yml`:

- `noisy-rules`: Per-rule quality/score penalties

### Touch Points

- **Depends on:** yara-python (compilation), yaraQA submodule, config
- **Called by:** `yara-forge.py` (pipeline stages 3 and 5)
- **Outputs to:** `yara-forge-rule-issues.yml`, adjusted rule quality scores

---

## yaraQA/ (Git Submodule)

### Purpose

Advanced rule quality and performance analysis. External project maintained separately.

### Repository

- URL: https://github.com/Neo23x0/yaraQA
- Location: `qa/yaraQA/`
- Managed via `.gitmodules`

### Key Components

| File | Purpose |
| ---- | ------- |
| `main/core.py` | Main analysis engine |
| `main/string_checks.py` | String atom analysis, regex performance |
| `main/condition_checks.py` | Condition logic validation |
| `main/combination_checks.py` | String/modifier compatibility |
| `main/performance_timer.py` | Baseline regex measurements |

### Capabilities

- Detects ReDoS-prone regex patterns
- Identifies rules with too many strings (resource warnings)
- Validates condition logic (e.g., `1 of them` with 1 string)
- Performance benchmarking against baseline patterns
- Returns issues with severity levels 1-3

### Integration

Called from `rule_qa.py` via:

```python
import qa.yaraQA.main.core as yara_qa
issues = yara_qa.analyze_rule(rule)
perf_issues = yara_qa.analyze_live_rule_performance(rule)
```

### Touch Points

- **Depends on:** pyre2 (regex analysis), test data
- **Called by:** `qa/rule_qa.py`
- **Outputs to:** Issue lists returned to caller
