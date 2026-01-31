# Glossary

Project-specific terms, abbreviations, and domain vocabulary.

## YARA Concepts

| Term | Definition |
| ---- | ---------- |
| **YARA** | Pattern matching tool for malware research; rules describe file characteristics |
| **YARA Rule** | A detection pattern with metadata, strings, and condition |
| **Condition** | Boolean expression that determines if a rule matches |
| **Strings** | Patterns (text, hex, regex) to search for in files |
| **Metadata** | Key-value pairs describing the rule (author, description, etc.) |
| **Private Rule** | A helper rule (marked `private`) used by other rules but not reported as a match |
| **Module** | YARA extension (pe, elf, hash, dotnet) providing additional matching capabilities |

## YARA Forge Concepts

| Term | Definition |
| ---- | ---------- |
| **Logic Hash** | Hash of a rule's condition, used for deduplication |
| **Quality Score** | Numeric score (0-100) indicating rule reliability; affects package inclusion |
| **Importance Score** | Manual override score for critical rules; bypasses quality thresholds |
| **Rule Set** | Collection of YARA rules from a single file |
| **Repository Set** | Collection of rule sets from a single source repository |
| **Package** | Generated `.yar` file containing filtered rules (core/extended/full) |
| **Noisy Rule** | Rule prone to false positives; penalized in custom scoring |

## Package Tiers

| Term | Quality Threshold | Score Threshold | Use Case |
| ---- | ----------------- | --------------- | -------- |
| **Core** | >= 70 | >= 65 | Production, low FP tolerance |
| **Extended** | >= 50 | >= 60 | Broader coverage, moderate FP |
| **Full** | >= 20 | >= 40 | Research, threat hunting |

## Issue Severity Levels

| Level | Name | Score Impact | Meaning |
| ----- | ---- | ------------ | ------- |
| **1** | Cosmetic | -2 | Minor style issues |
| **2** | Minor | -25 | Small performance impact |
| **3** | Major | -70 | Significant performance/logic issues |
| **4** | Critical | -1000 | Rule broken, excluded from output |

## Configuration Terms

| Term | Definition |
| ---- | ---------- |
| **repo_staging_dir** | Local directory where repositories are cloned |
| **yara_repositories** | List of source repositories in config |
| **rule_base_score** | Default score for rules without custom scoring |
| **meta_data_order** | Prescribed order for metadata fields in output |
| **force_include_importance_level** | Importance threshold to bypass quality filters |
| **force_exclude_importance_level** | Importance threshold to force exclusion |
| **minimum_age** | Minimum rule age (days) for package inclusion |
| **maximum_age** | Maximum rule age (days) for package inclusion |

## File Types

| Extension | Description |
| --------- | ----------- |
| `.yar`, `.yara` | YARA rule files |
| `.yml`, `.yaml` | YAML configuration files |
| `build_stats.md` | Build statistics for releases |
| `yara-forge.log` | Execution log |
| `yara-forge-rule-issues.yml` | QA findings report |

## Tools and Libraries

| Term | Definition |
| ---- | ---------- |
| **plyara** | Python library for parsing YARA rules |
| **yara-python** | Python bindings for YARA engine |
| **yaraQA** | Rule quality analysis tool (submodule) |
| **pyre2** | Python bindings for RE2 regex engine |
| **GitPython** | Python library for Git operations |

## Abbreviations

| Abbrev | Meaning |
| ------ | ------- |
| **QA** | Quality Assurance |
| **FP** | False Positive |
| **UUID** | Universally Unique Identifier |
| **LFS** | Large File Storage (Git extension) |
| **ReDoS** | Regular expression Denial of Service |
| **CI/CD** | Continuous Integration / Continuous Deployment |

## Source Repository Identifiers

Common repository name prefixes in generated rules:

| Prefix | Source |
| ------ | ------ |
| `SIGNATURE_BASE_` | Florian Roth's Signature Base |
| `GODMODE_` | GodModeRules |
| `REVERSINGLABS_` | ReversingLabs YARA rules |
| `CAPE_` | CAPE Sandbox rules |
| `MALPEDIA_` | Malpedia project |
| `GCTI_` | Google Cloud Threat Intelligence |
| `ELASTIC_` | Elastic Security rules |
| `DELIVRTO_` | Delivr.to threat intelligence |
