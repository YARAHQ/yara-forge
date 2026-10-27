# Design Decisions

Notable architecture and design choices in YARA Forge.

## Logic Hash Deduplication

**Decision:** Deduplicate rules by condition logic hash, not by rule name.

**Rationale:** Different repositories may contain functionally identical rules with different names. Using plyara's `generate_hash()` on rule conditions identifies truly duplicate detection logic, regardless of naming conventions.

**Implication:** The first occurrence of a rule (by processing order) wins. Private rules are excluded from deduplication to preserve dependencies.

---

## Three-Tier Package System

**Decision:** Generate three package tiers (core, extended, full) with different quality thresholds.

**Rationale:** Different use cases have different tolerance for false positives:

- **Core:** Production systems need highest quality
- **Extended:** Threat hunting accepts moderate noise
- **Full:** Research benefits from comprehensive coverage

**Implication:** Users choose the appropriate tier for their environment. Importance levels can override thresholds for critical rules.

---

## Rule Name Prefixing

**Decision:** Prefix all rule names with repository identifier (e.g., `SIGNATURE_BASE_original_name`).

**Rationale:**

- Ensures unique rule names across merged packages
- Provides attribution to source repository
- Aids debugging by identifying rule origin

**Implication:** Original rule names are preserved in `old_rule_name` metadata field.

---

## UUIDv5 for Rule Identification

**Decision:** Generate deterministic UUIDs from logic hashes using UUIDv5.

**Rationale:**

- Provides stable identifiers across builds
- Same rule logic always gets same UUID
- Enables tracking rules across versions

**Implication:** UUIDs change if rule logic changes, but remain stable for identical rules.

---

## Custom Scoring via YAML

**Decision:** Allow per-rule scoring overrides in `yara-forge-custom-scoring.yml`.

**Rationale:**

- Some rules are known to be noisy (false positive prone)
- Some rules are critical despite lower automatic scores
- Manual curation improves package quality

**Implication:** Maintainers must actively curate the custom scoring file. Supports prefix matching for rule families.

---

## Four-Level Severity System

**Decision:** Use four severity levels (1-4) for QA issues.

**Rationale:**

- Level 4 (critical): Rules that don't compile must be excluded
- Level 3 (major): Significant performance/logic issues warrant large penalties
- Level 2 (minor): Small issues should affect filtering
- Level 1 (cosmetic): Minor issues shouldn't exclude rules

**Implication:** Score adjustments are configurable in `issue_levels` config.

---

## Private Rule Dependency Tracking

**Decision:** Automatically track and include private rules needed by public rules.

**Rationale:**

- Private rules are helper rules used by other rules
- Without their dependencies, public rules would fail to compile
- Manual tracking would be error-prone

**Implication:** Private rules are:

- Excluded from deduplication (each repo keeps its own)
- Renamed with repo prefix like public rules
- Condition references rewritten to use new names
- Prepended to output before dependent rules

---

## yaraQA as Git Submodule

**Decision:** Include yaraQA as a git submodule rather than copying code.

**Rationale:**

- yaraQA is maintained as a separate project
- Submodule allows independent version tracking
- Updates can be pulled without code duplication

**Implication:** Submodule must be initialized (`git submodule update --init`).

---

## Sparse Checkout for Large Repositories

**Decision:** Support sparse checkout via `path` config option.

**Rationale:**

- Some repositories contain YARA rules in subdirectories
- Cloning entire large repositories wastes bandwidth
- Sparse checkout fetches only needed paths

**Implication:** Repositories with `path` specified only clone that subdirectory.

---

## Git History for Rule Dates

**Decision:** Extract rule dates from git commit history when metadata is missing.

**Rationale:**

- Many rules lack date metadata
- Git history provides reliable creation/modification dates
- Enables age-based filtering without manual annotation

**Implication:** Rules without git history default to current date.

---

## Skip Git LFS

**Decision:** Skip Git LFS smudge operations during clone.

**Rationale:**

- LFS files are typically large binaries (samples, test data)
- YARA rules are plain text, not stored in LFS
- Skipping LFS significantly speeds up cloning

**Implication:** Any repository storing YARA rules in LFS would fail (none known).

---

## Open Questions (TODO)

### Repository Selection Criteria

**Question:** What criteria are used to vet new repositories for inclusion?

**Context:** The config includes 45+ repositories marked as "carefully selected." The criteria for selection are not documented.

### ELF Module Score Cap

**Question:** Why are ELF module rules capped at score 40?

**Context:** Code in `rule_processors.py` caps ELF rules at 40. Rationale not documented.

### Custom Scoring Prefix Matching

**Question:** What is the full matching logic for custom scoring rules?

**Context:** Supports `type: "prefix"` but exact matching semantics need verification.
