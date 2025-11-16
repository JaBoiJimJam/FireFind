# FireFind Rules Configuration Schema

The rules configuration governs how FireFind classifies and prioritises firewall
findings.  The schema now supports rich metadata for risk levels, reusable port
collections, and granular CIDR limits.  This document summarises each section,
explains the migration path from legacy keys, and highlights the new rationale
fields that power executive-ready reporting.

## File Location & Loading

FireFind loads configuration from a YAML file passed to the CLI via
`--rules`. When no file is supplied the built-in defaults from
`firefind.config.DEFAULT_RULES_CONFIG` are used. The loader merges the user file
with these defaults recursively, so partial overrides only need to specify the
fields they change. Legacy files that only contain the original keys (such as
`admin_ports` and `broad_cidr_prefix_max`) continue to function without
modification.

## Administrative Port Sets

| Key                          | Description |
|-----------------------------|-------------|
| `admin_ports`               | Baseline administrative ports tracked for exposure. |
| `critical_risk_admin_ports` | Subset of ports treated as "Critical" if exposed. |
| `high_risk_admin_ports`     | Ports escalated as "High" severity. |
| `medium_risk_admin_ports`   | Ports escalated as "Medium" severity. |
| `low_risk_admin_ports`      | Ports escalated as "Cautionary" severity when no stricter tier applies. |

Values can be integers or strings. The loader validates ranges and merges each
subset into the overall `admin_ports` list to preserve backwards compatibility
with the existing rule engine.

## Risk Level Definitions

The `risk_levels` map introduces structured metadata for each qualitative risk
category. Every entry supports the following fields:

- `label`: Human-friendly display name used in reports.
- `severity`: One of `critical`, `high`, `medium`, `cautionary`, `low`, or `informational`.
- `thresholds`: Numeric guardrails represented by
  [`NumericThresholds`](../src/firefind/config/schema.py). Supported keys include
  `min_score`, `max_score`, `min_findings`, and `max_findings`. Validation ensures
  minimum values do not exceed maximums.
- `rationale`: Captured by [`Rationale`](../src/firefind/config/schema.py) with
  `summary`, optional `details`, and a list of `references`. This metadata feeds
  executive summaries and migration notes.

Existing automation that only relies on severity strings may ignore this
section—the loader still provides legacy key/value access via
`RulesConfig.get_legacy_mapping()`.

## CIDR Limit Sets

CIDR limit sets describe how wide network ranges may be before they are flagged
as risky. They support layered overrides:

- `default`: Base policy applied to all vendors/directions.
- `analyzers`: Named overrides for specific analyzers (e.g. `admin_port_exposed`).
- `vendors`: Overrides keyed by vendor name (case-insensitive).
- `directions`: Overrides keyed by traffic direction such as `inbound` or
  `outbound`.
- `vendor_direction_overrides`: Most specific policy keyed by vendor, then
  direction.

Each policy is a [`CIDRLimitPolicy`](../src/firefind/config/schema.py) with the
following fields:

- `max_prefix` / `min_prefix`: Inclusive prefix bounds (validated between 0 and 128).
- `blocked`: List of CIDRs automatically treated as violations.
- `exempt`: List of CIDRs excluded from enforcement.
- `description`: Optional documentation string to capture business context.

Use the [`CIDRLimitSet.resolve`](../src/firefind/config/schema.py) method to
retrieve the most specific policy for a given vendor, direction, and analyzer.

### Migration Guidance

Legacy configurations that only rely on `broad_cidr_prefix_max` remain valid.
When both values are present the explicit limit in the CIDR set takes precedence
but the scalar is still exposed via `RulesConfig.broad_cidr_prefix_max` for the
existing rules engine.

## Reusable Port Groups

The `port_groups` collection enables the reuse of curated port definitions across
analyzers or reporting layers. Each entry expands to a
[`PortGroup`](../src/firefind/config/schema.py) with:

- `description`: Markdown-friendly explanation of the group's intent.
- `protocol`: `tcp`, `udp`, or `any` (validated).
- `ranges`: List of integers, `start-end` strings, or mappings containing
  `start`/`end` keys. Validation ensures ranges fall within `1-65535` and do not
  overlap within the same group.

The loader flattens each range into an explicit set of ports so analyzers can
perform quick membership checks. Helpers on
[`PortGroupCollection`](../src/firefind/config/schema.py) return the flattened
sets (`port_sets`), identify which groups cover an arbitrary port
(`groups_for_port`), or intersect a list of ports with all compatible groups
(`port_memberships`).

These canonical names now flow directly into admin-port reporting: when a rule
exposes multiple curated groups, FireFind emits one finding per group with
`port_profile` set to the group key (for example `ldap_related_ports` or
`remote_shell_ports`). The deterministic rationale of each finding lists the
matched ports, allowing `deduplicate_findings` to collapse repeat hits for the
same source/destination/protocol tuple automatically. Leftover ports that do not
belong to any configured group continue to fall back to the heuristic
`_port_profile` classifications.

## Rule Logic Definitions

Rule logic is captured in the `rules` map. Every rule contains three key
components:

1. **Base definition** (`id`, `label`, `description`) that drives UI copy and
   reporting labels.
2. **Condition groups** expressed with `logic: all|any` and lists of field
   comparators. Conditions support rich comparators such as `matches_port_group`,
   numeric thresholds, and nested groups for OR logic.
3. **Analyzer metadata** that toggles analyzers on/off, maps severities, and
   links administrative port tiers back to the global lists.

See [`RuleDefinition`](../src/firefind/config/schema.py) for the Python data
model and [`types/rules-config.ts`](../../types/rules-config.ts) for the matching
TypeScript contract with Zod validation helpers. The migration utilities in
[`config.migrations`](../src/firefind/config/migrations.py) automatically
populate this structure when loading legacy YAML files that lack the `rules`
section.

## Rationale Fields

Rationale metadata provides traceability for risk decisions. Populate
`summary` for quick context, `details` for deeper justification, and `references`
for authoritative sources (frameworks, regulations, or internal policies).
Surface these fields in executive briefings or ticketing automations to
accelerate remediation.

## Example Configuration

See [`rules.config.sample.yaml`](../../rules.config.sample.yaml) for a
fully-commented example that exercises each schema feature. Start by copying the
file and tailoring the port groups, CIDR limits, and risk rationale to your
organisation's standards.