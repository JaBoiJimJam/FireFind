# FireFind Operator Guide

This runbook explains how to configure, deploy, and maintain the FireFind backend
in production environments. It focuses on day-two operations for the CLI and
FastAPI services.

## 1. Prepare Configuration Assets

1. **Clone or update the repository** and review `rules.config.sample.yaml` for
   the latest schema capabilities.
2. **Create a dedicated configuration directory** on shared storage that is
   readable and writable by the FireFind process.
3. **Copy and customize** the sample file, adjusting:
   - Risk level thresholds and rationale.
   - CIDR policies for inbound and outbound traffic.
   - Administrative port collections and reusable port groups.
4. **Set environment variables** for the runtime (see table below). Store
   secrets such as `FIRE_FIND_API_TOKEN` in your secret manager.

| Variable | Description |
| --- | --- |
| `FIRE_FIND_RULES_CONFIG` | Absolute path to the primary rules configuration file. |
| `FIRE_FIND_RULES_HISTORY` | Optional override for the JSONL history log. |
| `FIRE_FIND_API_TOKEN` | Bearer token used to authenticate configuration API requests. |
| `FIRE_FIND_ALLOW_ORIGINS` | Comma-separated allow-list for browser clients; defaults to `*`. |

## 2. Deploy the Backend Service

FireFind can run as a CLI job or as a FastAPI service. Production deployments
commonly host the FastAPI server behind an HTTPS reverse proxy.

### CLI Batch Runs

- Export the environment variables noted above.
- Invoke the CLI wrapper with the appropriate vendor input directory:
  ```bash
  cd /opt/firefind/backend
  python run_backend.py --input /data/firewall_exports --out /var/firefind/out
  ```
- Schedule recurring scans via cron or a workflow engine and archive the
  generated CSV/PDF reports.

### FastAPI Service

1. Ensure the Python path includes `backend/src`.
2. Launch the service with your preferred ASGI host, for example:
   ```bash
   uvicorn firefind.api:app --host 0.0.0.0 --port 8080
   ```
3. Configure your process manager (systemd, Docker, Kubernetes, etc.) to restart
   the service on failure and to inject the environment variables from step 1.
4. Restrict inbound access to the `/api/config/*` endpoints to trusted operator
   networks.

## 3. Manage Configuration Revisions

The FastAPI configuration endpoints provide a lightweight change-management
workflow:

1. Issue authenticated `GET /api/config/rules` requests to review the active
   configuration and revision metadata.
2. Submit targeted updates with `PATCH /api/config/rules`, supplying the
   `Authorization: Bearer <token>` header and optional `X-Firefind-Actor`
   attribution.
3. Monitor the JSONL history file for a durable audit trail of who changed what
   and when. Consider shipping the history to your central log store.
4. Use `GET /api/config/rules/history?limit=20` to confirm the system recorded
   the revision before notifying downstream teams.

## 4. Backup and Recovery

- **Primary files**: the rules configuration and its history log. Take nightly
  snapshots or integrate them with your existing backup tooling.
- **Disaster recovery**: restore the latest configuration file and history log,
  then restart the service. No additional database migrations are required.
- **Validation**: after a restore, call the configuration API to verify the
  version, timestamps, and expected actor information.

## 5. Monitoring and Alerting

- Track job success/failure via the wrapper script's exit codes.
- Expose FastAPI health checks behind your load balancer and alert on HTTP 5xx
  trends.
- Watch the history log for unusually frequent or unauthorized changes to the
  rules.

## 6. Operator Handover Checklist

- [ ] Environment variables stored in the appropriate secret store.
- [ ] Configuration directory backed up and access-controlled.
- [ ] Process manager configured with restart policy and logging.
- [ ] Runbooks distributed to on-call engineers and SOC operators.

Keeping this checklist current ensures that future updates to the rules schema
or analyzers can be rolled out without service disruption.