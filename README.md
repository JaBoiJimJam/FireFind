# FireFind
Firewall Risk Identification Tool
<!-- Markdown version -->
![My Project Logo](public/firefind_logo.jpg)

## Problem and Audience
FireFind helps security teams quickly pinpoint risky firewall rules that slip
through manual reviews. Network administrators, security auditors, and
compliance staff can use the tool to understand how existing rules expose their
organisations to unnecessary network access.

## Background: Rule Bloat and Misconfiguration
Years of firewall changes often lead to bloated policies with overly permissive
or forgotten rules. Misconfigurations and rule sprawl increase attack surface
and make it difficult to maintain least‑privilege access. Automating analysis of
these rule sets reduces the chance of human error and speeds up remediation.

## Objectives, Functional Requirements, and Scope
### Objectives
- Automate detection of risky firewall rules.
- Provide actionable reporting for remediation.
- Enable cross‑vendor rule comparison to promote consistent security practices.

### Functional Requirements
- Ingest rule exports from supported firewall platforms.
- Analyse rules for overly broad access, shadowing, and unused entries.
- Present findings in formats suitable for auditors and engineers.

### Scope
**Must‑Haves**
- Parse and evaluate rule sets.
- Highlight high‑risk or redundant rules.

**Nice‑to‑Haves**
- Generate remediation suggestions.
- Provide an interactive interface for filtering and sorting results.

**Optional**
- Integrate with ticketing or change‑management systems.
- Support for cloud‑based firewall services.

## Triskele Labs Vision
Triskele Labs aims to deliver vendor‑agnostic rule analysis across major
firewall providers. FireFind will grow to parse and assess policies from
Fortinet, Sophos, Barracuda, Checkpoint, and WatchGuard, giving organisations a
consistent view of firewall risk regardless of platform.
