# YARA Forge

Automated YARA Rule Standardization and Quality Assurance Tool

YARA Forge collects YARA rules from 45+ vetted security repositories, standardizes their metadata, performs multi-level quality checks, and generates tiered rule packages (core/extended/full) ready for integration into security products. It handles deduplication, private rule dependencies, and custom scoring to produce consistent, reliable rule sets for malware detection and threat hunting.

The tool is used by security teams and analysts who need curated YARA rules without manually managing multiple sources. Weekly releases are published automatically via GitHub Actions.

## Components

- `yara-forge.py` — CLI entry point and pipeline orchestrator
- `main/` — Rule collection, processing, and output generation
- `qa/` — Quality assurance checks and validation
- `packages/` — Generated rule packages (core, extended, full)

## Documentation

- **[Project Map / IKL](./docs/index.md)** — Navigation guide for the codebase
- [Architecture](./docs/architecture.md) — System design and data flows
- [Code Structure](./docs/code-structure.md) — API reference for modules and functions

## Quick Links

- [YARA Forge Website](https://yarahq.github.io/) — Official project page
- [GitHub Releases](https://github.com/YARAHQ/yara-forge/releases) — Weekly rule packages

> **Note:** The repositories used for YARA Forge have been carefully selected. Adding unvetted sources is not supported.
