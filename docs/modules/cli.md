# Module: CLI Entry Point

The main orchestrator for the YARA Forge pipeline.

## File

| File | Lines | Purpose |
| ---- | ----- | ------- |
| `yara-forge.py` | ~100 | CLI parsing, logging setup, pipeline execution |

## Purpose

Entry point that:

- Parses command-line arguments
- Configures logging (console and file)
- Loads configuration from YAML
- Executes pipeline stages in sequence
- Reports progress via section headers

## CLI Arguments

| Argument | Description | Default |
| -------- | ----------- | ------- |
| `--debug` | Enable debug output to console | INFO level |
| `-c`, `--config` | Path to config file | `yara-forge-config.yml` |

## Usage

```bash
# Standard run
python yara-forge.py

# Debug mode with custom config
python yara-forge.py --debug -c yara-forge-config-testing.yml
```

## Pipeline Execution

The main function executes these stages in order:

```python
# 1. Collection
yara_rule_repo_sets = retrieve_yara_rule_sets(
    config['repo_staging_dir'],
    config['yara_repositories']
)

# 2. Processing
processed_yara_repos = process_yara_rules(
    yara_rule_repo_sets,
    config
)

# 3. Quality Assurance
evaluated_yara_repos = evaluate_rules_quality(
    processed_yara_repos,
    config
)

# 4. Output Generation
repo_files = write_yara_packages(
    evaluated_yara_repos,
    PROGRAM_VERSION,
    get_yara_qa_commit_hash(),
    config
)

# 5. Validation
check_yara_packages(repo_files)
```

## Logging Configuration

### Console Handler

- Level: INFO (or DEBUG with `--debug`)
- Format: `%(message)s` (minimal)

### File Handler

- File: `yara-forge.log`
- Level: DEBUG (always)
- Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`

### Suppressed Loggers

- `plyara` (set to WARNING)
- `tzlocal` (set to WARNING)

## Helper Functions

| Function | Purpose |
| -------- | ------- |
| `write_section_header(title, divider_width=72)` | Print formatted section dividers |

## Configuration Loading

Reads YAML config file specified by `-c` argument:

```python
with open(args.config, 'r') as f:
    config = yaml.safe_load(f)
```

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| 0 | Success (all packages validated) |
| 1 | Failure (package validation failed) |

## Touch Points

- **Depends on:** All modules (`main/`, `qa/`), config files
- **Imports from:**
  - `main.rule_collector.retrieve_yara_rule_sets`
  - `main.rule_processors.process_yara_rules`
  - `qa.rule_qa.evaluate_rules_quality`
  - `qa.rule_qa.check_yara_packages`
  - `qa.rule_qa.get_yara_qa_commit_hash`
  - `main.rule_output.write_yara_packages`
- **Outputs:** Console output, `yara-forge.log`
