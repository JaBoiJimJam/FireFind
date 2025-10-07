# FireFind Deployment Migration Checklist

Use this checklist when upgrading an existing FireFind deployment to the latest
backend release. It focuses on safeguarding configuration state and validating
analysis outputs after the upgrade.

## 1. Pre-Migration Preparation

- [ ] Review the release notes and rules schema changes in
      `backend/docs/rules-config.md`.
- [ ] Confirm maintenance windows with stakeholders and notify downstream report
      consumers.
- [ ] Verify operator access to the runtime hosts, configuration directory, and
      object storage bucket (if applicable).

## 2. Backup Existing State

- [ ] Export the active configuration via `GET /api/config/rules` and store the
      JSON payload securely.
- [ ] Copy the on-disk rules file referenced by `FIRE_FIND_RULES_CONFIG` to a
      timestamped backup location.
- [ ] Archive the revision history file (`*.history.jsonl`) referenced by
      `FIRE_FIND_RULES_HISTORY`.
- [ ] Capture the most recent CSV/PDF reports so that analysts can compare
      results post-migration.

## 3. Validate Prerequisites

- [ ] Ensure the target hosts meet the Python version and dependency
      requirements from `backend/requirements.txt`.
- [ ] Confirm that the environment variables listed in the operator guide are
      present in your process manager or secrets store.
- [ ] Run unit tests or a smoke scan in a staging environment when possible.

## 4. Execute the Upgrade

- [ ] Pull the latest code (`git pull` or deploy artifact sync).
- [ ] Reinstall Python dependencies using `pip install -r requirements.txt`.
- [ ] Apply infrastructure changes (systemd unit updates, container images,
      deployment manifests) with configuration values intact.
- [ ] Restart the FireFind service or job runners.

## 5. Post-Migration Validation

- [ ] Trigger a sample scan against known-good firewall exports.
- [ ] Compare the generated findings with the pre-migration reports and note any
      expected rule changes.
- [ ] Query `GET /api/config/rules/history?limit=5` to ensure the revision log is
      still accessible and recording new entries.
- [ ] Check service logs and monitoring dashboards for errors or unusual latency.

## 6. Sign-Off

- [ ] Share validation results with stakeholders and obtain sign-off.
- [ ] Update internal documentation with any new operational nuances observed
      during the migration.
- [ ] Close out change-management tickets and store backups according to your
      retention policy.

Following this checklist helps teams upgrade confidently while preserving the
configuration history that underpins audit readiness.