# FireFind (Sprint 1 Starter)

A minimal, client-demo-ready starter for the **FireFind** MVP. It ingests a firewall rule export (CSV/XLSX), normalizes the data, runs minimal risk checks, and outputs **findings.csv** and a **report.pdf**.

## Quickstart

```bash
python -m pip install -r requirements.txt

# Run demo on sample CSV (Fortinet placeholder sample)
python src/firefind/cli.py parse   --vendor fortinet   --input samples/fortinet_sample.csv   --out-csv out/findings.csv   --out-pdf out/report.pdf   --rules rules/rules.yaml   --mappings rules/vendor_mappings.yaml
```

Outputs:
- `out/findings.csv` – technical findings
- `out/report.pdf` – stakeholder summary (counts + top risks)

> Note: The sample CSV is simplified and already close to the normalized schema. For real vendor exports, update `rules/vendor_mappings.yaml` to map columns → normalized fields.
