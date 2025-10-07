# FireFind Manual QA Runbook

This runbook provides the repeatable manual checks required before cutting a
FireFind release. It focuses on validating rule authoring, YAML parity with the
backend schema, and legacy compatibility for downstream tooling.

## 1. Environment Preparation

1. Install backend dependencies: `pip install -r backend/requirements.txt`.
2. Install frontend tooling: `npm install`.
3. Launch the integrated development server from the project root:
   ```bash
   ./start_dev.sh
   ```
4. Set the following environment variables in your shell (matching CI defaults):
   ```bash
   export FIRE_FIND_API_TOKEN=qa-token
   export FIRE_FIND_RULES_CONFIG=backend/rules/rules.yaml
   export FIRE_FIND_RULES_HISTORY=backend/rules/rules.history.jsonl
   ```
5. Open `http://127.0.0.1:8000/admin.html` in a modern browser.

## 2. Rule Editing Smoke Test

1. In the Admin console, select **Add Rule Definition** and confirm that an empty
   card appears.
2. Click **Edit** on the new card. Populate the modal with:
   - Rule identifier, ID, and label (use `admin_port_exposed`).
   - At least one condition (`action` equals `allow`).
   - Analyzer key matching the identifier.
3. Save the rule and confirm:
   - The modal closes without validation errors.
   - The rule card header reflects the configured label.
   - The toast banner reports a successful save.
4. Toggle the rule disabled and re-enabled. Ensure validation summary remains
   green and no error toast is shown.
5. Delete the rule using the trash icon and confirm the empty state message
   returns.

## 3. YAML Parity Verification

1. Recreate the rule from step 2 and configure a second condition using the
   nested group UI (ANY group with a `destination_port` equals `22` condition).
2. Export the configuration via **Export YAML Snapshot** and save the generated
   file.
3. Fetch the API payload:
   ```bash
   curl -H "Authorization: Bearer $FIRE_FIND_API_TOKEN" \
        http://127.0.0.1:8000/api/config/rules > /tmp/rules.json
   ```
4. Convert the JSON to YAML for comparison: `yq eval /tmp/rules.json > /tmp/rules.yaml`.
5. Diff the exported YAML with `/tmp/rules.yaml` and verify rule metadata,
   condition trees, analyzer overrides, and thresholds match.
6. Import the previously exported YAML using **Import YAML Snapshot** and confirm
   the UI rehydrates identical cards without additional validation errors.

## 4. Legacy Compatibility Checks

1. Execute the CLI against the sample configuration to ensure `RulesConfig`
   continues to emit legacy dictionary structures:
   ```bash
   PYTHONPATH=backend/src python - <<'PY'
   from firefind.config.loader import load_rules_config

   cfg = load_rules_config('backend/samples/rules.minimal.yaml')
   legacy = cfg.get_legacy_mapping()
   assert isinstance(legacy, dict)
   assert 'admin_ports' in legacy and isinstance(legacy['admin_ports'], list)
   PY
   ```
2. Run the `backend/run_backend.py` sample workflow and confirm reports generate
   without schema errors.
3. Open the admin console and ensure rules imported from
   `backend/samples/rules.minimal.yaml` display identical labels, analyzer
   assignments, and thresholds.

## 5. Sign-Off Criteria

- [ ] Rule creation, editing, enable/disable toggles, and deletion confirmed.
- [ ] Exported YAML matches API payloads (no data loss in round-trips).
- [ ] Imported YAML rehydrates UI state without new validation warnings.
- [ ] Legacy dict view (`get_legacy_mapping`) retains structure expected by
      automation scripts.
- [ ] CLI sample run produces findings with no regressions in stdout or logs.
- [ ] Findings and manual observations recorded in `reports/manual-qa-<date>.md`.

Completing the above ensures FireFind rule management remains aligned with the
backend schema while preserving compatibility for operators relying on the
legacy dictionary view.
