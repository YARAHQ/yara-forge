# YARA Forge - Technical Code Structure

## Project Structure

```
yara-forge/
├── yara-forge.py              # CLI entry point
├── main/
│   ├── __init__.py
│   ├── other_evals.py         # Performance testing
│   ├── rule_collector.py      # Repo fetching/extraction
│   ├── rule_output.py         # Package generation
│   └── rule_processors.py     # Rule standardization/evaluation
├── qa/
│   ├── __init__.py
│   ├── rule_qa.py             # Quality assurance & checks
│   └── yaraQA/                # Submodule (yaraQA tools?)
├── tests/                     # Unit tests
├── configs (*.yml)            # Configs
└── requirements.txt
```

## Entry Point: `yara-forge.py`

- `write_section_header(title, divider_with=72)`: Prints formatted section headers.
- Main: Parses args (`--debug`, `-c`), logging setup, config load, pipeline: `retrieve_yara_rule_sets` → `process_yara_rules` → `evaluate_rules_quality` → `write_yara_packages` → `check_yara_packages`.

## main/

### other_evals.py
- `class PerformanceTimer`:
  - `__init__()`: Initializes timer.
  - `baseline_measurements()`: Runs baseline perf tests.
  - `test_regex_performance(regex, iterations=5)`: Benchmarks regex.

### rule_collector.py
- `process_yara_file(file_path, repo_folder, yara_rule_sets)`: Processes single YARA file.
- `retrieve_yara_rule_sets(repo_staging_dir, yara_repos)`: Clones repos, extracts rules into sets.

### rule_output.py
- `write_yara_packages(processed_yara_repos, program_version, yaraqa_commit, YARA_FORGE_CONFIG)`: Generates .yar packages.
  - Inner: `_normalize_datetime(dt_value)`: Normalizes dates.
- `write_build_stats(rule_package_statistics_sets)`: Writes stats.

### rule_processors.py
Core standardization:
- `process_yara_rules(yara_rule_repo_sets, YARA_FORGE_CONFIG)`: Main processor.
- `add_tags_to_rule(rule)`: Adds tags.
- `retrieve_custom_importance_score(repo_name, file_path, rule_name)`: Custom scores.
- `sort_meta_data_values(rule_meta_data, YARA_FORGE_CONFIG)`: Sorts meta.
- `adjust_identifier_names(repo_name, condition_terms, private_rules_used)`: Fixes IDs.
- `check_rule_uses_private_rules(repo_name, rule, ext_private_rule_mapping)`: Private rule check.
- Alignment funcs:
  - `align_yara_rule_description/rule_meta_data, repo_description)`
  - `align_yara_rule_hashes(rule_meta_data)`
  - `align_yara_rule_author(rule_meta_data, repo_author)`
  - `align_yara_rule_uuid(rule_meta_data, uuid)` (uses `is_valid_uuidv5`, `generate_uuid_from_hash`)
  - `align_yara_rule_name(rule_name, rule_set_id)`
  - `align_yara_rule_reference(rule_meta_data, rule_set_url)`
  - `align_yara_rule_date(rule_meta_data, repo_path, file_path)` (uses `get_rule_age_git`)
- `evaluate_yara_rule_score(rule, YARA_FORGE_CONFIG)` / `evaluate_yara_rule_meta_data(rule)`: Scoring.
- `modify_yara_rule_quality(rule_meta_data, reduction_value)` / `modify_meta_data_value(rule_meta_data, key, value)`: Mods.

## qa/

### rule_qa.py
- `evaluate_rules_quality(processed_yara_repos, config)`: Quality eval.
- `write_issues_to_file(rule_issues)`: Logs issues.
- `retrieve_custom_quality_reduction/score(rule)`: Custom QA.
- `check_syntax_issues/rule)` / `check_issues_critical(rule)`: Syntax/critical checks.
- `check_yara_packages(repo_files)`: Final validation.
- `get_yara_qa_commit_hash()`: QA commit.
- `modify_yara_rule_quality/meta_data_value`: Shared mods.

## Dependencies & Configs
- Python libs for YARA parse (plyara), git, YAML, regex (re2).
- `yara-forge-config.yml`: Repos, thresholds.
- `yara-forge-custom-scoring.yml`: Scoring rules.

## Notes
- Functions are procedural; few classes.
- Pipeline modular, config-driven.
- Tests in `tests/` cover collector, processors, output guardrails.

For source: Inspect individual files.
