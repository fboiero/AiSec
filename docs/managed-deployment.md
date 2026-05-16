# AiSec Managed Deployment Path

This guide defines the path for running AiSec as a shared service for
orchestrators, compliance systems, and CI/CD platforms.

Use CLI mode for local CI. Use managed service mode when multiple projects need
centralized evaluation history, baseline approval, exceptions, rollups, and
dashboard/API access.

## Deployment Modes

| Mode | Best for | Entry point |
| --- | --- | --- |
| CLI in CI | One repository or one pipeline | `aisec evaluate model` |
| Docker Compose | Single VM, demo, pilot, internal lab | `deploy/docker-compose.prod.yml` |
| Kubernetes manifests | Controlled cluster deployment | `deploy/kubernetes/` |
| Helm | Managed multi-environment deployment | `deploy/helm/aisec/` |

## Service Surface

Managed mode should expose only the API and dashboard behind an ingress or
private network boundary.

Core endpoints:

```text
GET  /api/live/
GET  /api/ready/
GET  /api/schema/
GET  /api/docs/
POST /api/evaluate/model/
GET  /api/evaluations/
GET  /api/evaluations/rollup/
POST /api/evaluation-baselines/
POST /api/evaluation-baselines/{baseline_id}/compare/
POST /api/evaluation-exceptions/
```

`/api/live/` is the liveness probe. `/api/ready/` checks dependencies and is the
readiness probe.

## Reference Architecture

```text
orchestrator or CI
  -> private ingress / API gateway
  -> AiSec API replicas
  -> persistent SQLite volume for history, baselines, exceptions, audit
  -> optional report volume / cloud storage
```

The current managed deployment is intentionally compact: SQLite plus persistent
volumes are enough for pilots and internal deployments. A future enterprise
deployment can replace persistence with a managed database without changing the
model-risk API contract.

## Docker Compose Pilot

```bash
cd deploy
export AISEC_SECRET_KEY="$(openssl rand -hex 32)"
docker compose -f docker-compose.prod.yml up -d
curl -f http://localhost:8000/api/live/
curl -f http://localhost:8000/api/ready/
```

Then submit an evaluation:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  --data @../docs/examples/orchestai-usecase-customer-support-rag.json \
  http://localhost:8000/api/evaluate/model/
```

Or run the managed API smoke script:

```bash
AISEC_BASE_URL=http://localhost:8000 \
  scripts/smoke-managed-api.sh
```

Capture pilot evidence before and after changes:

```bash
AISEC_BASE_URL=http://localhost:8000 \
AISEC_EVIDENCE_DIR=aisec-managed-evidence/pre-upgrade \
  scripts/capture-managed-evidence.sh
```

For external pilots, run the full rehearsal wrapper:

```bash
AISEC_BASE_URL=http://localhost:8000 \
AISEC_REHEARSAL_ID=pilot-001 \
  scripts/rehearse-managed-pilot.sh
```

The rehearsal captures pre-smoke evidence, runs the managed API smoke check,
captures post-smoke evidence, and writes a small run report.

## Kubernetes Pilot

```bash
kubectl create namespace aisec
kubectl -n aisec create secret generic aisec-secrets \
  --from-literal=AISEC_SECRET_KEY="$(openssl rand -hex 32)"
kubectl apply -n aisec -f deploy/kubernetes/
kubectl -n aisec rollout status deploy/aisec-api
kubectl -n aisec get pods
```

If using the checked-in `secret.yaml`, replace placeholder values before
deploying. Prefer cluster-native secret management for shared environments.

## Helm Deployment

```bash
helm upgrade --install aisec deploy/helm/aisec \
  -n aisec \
  --create-namespace \
  --set secrets.secretKey="$(openssl rand -hex 32)"
```

Production overrides should set:

```yaml
image:
  tag: "1.10.0"
ingress:
  enabled: true
  hosts:
    - host: aisec.internal.example.com
      paths:
        - path: /
          pathType: Prefix
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: "2"
    memory: 4Gi
persistence:
  data:
    enabled: true
    size: 10Gi
  reports:
    enabled: true
    size: 25Gi
```

## Security Baseline

Minimum controls for managed mode:

- Put AiSec behind private ingress, VPN, or API gateway.
- Set `AISEC_SECRET_KEY` to a random secret.
- Enable API authentication when exposing beyond a trusted network.
- Enforce TLS at ingress.
- Restrict Docker socket access to environments that need deep scans.
- Back up the `/data` volume that stores history, baselines, exceptions, and
  audit events.
- Keep `/api/docs/` private if it exposes internal deployment URLs.

## Operations Checklist

Before go-live:

- `GET /api/live/` returns 200.
- `GET /api/ready/` returns 200.
- `POST /api/evaluate/model/` stores a model-risk evaluation.
- `GET /api/evaluations/rollup/` returns posture data.
- `scripts/smoke-managed-api.sh` passes against the deployed service URL.
- `scripts/capture-managed-evidence.sh` captures live, ready, OpenAPI,
  rollup, evaluations, baselines, and exceptions.
- `scripts/rehearse-managed-pilot.sh` creates a complete pilot evidence
  package with pre-smoke and post-smoke captures.
- Baseline creation and comparison work for one approved target.
- Exception creation and expiry behavior are tested.
- Persistent volume survives pod restart.
- Logs include enough context to correlate request failures.
- Backup and restore procedure for `/data` is documented.

## Upgrade Path

1. Deploy the new image tag into staging.
2. Run the two validated OrchestAI use cases.
3. Run `scripts/smoke-managed-api.sh` against the staging URL.
4. Verify `/api/schema/` for expected paths.
5. Confirm existing evaluations, baselines, and exceptions still list.
6. Promote to production with a rolling update.
7. Keep the previous image tag available for rollback.

## Evidence Capture

Capture service evidence before upgrades, after upgrades, and after rollbacks:

```bash
AISEC_BASE_URL=https://aisec.internal.example.com \
AISEC_EVIDENCE_DIR=aisec-managed-evidence/pre-upgrade \
  scripts/capture-managed-evidence.sh

AISEC_BASE_URL=https://aisec.internal.example.com \
AISEC_EVIDENCE_DIR=aisec-managed-evidence/post-upgrade \
  scripts/capture-managed-evidence.sh
```

The evidence directory includes:

- `live.json`
- `ready.json`
- `openapi.json`
- `model-risk-rollup.json`
- `model-risk-evaluations.json`
- `model-risk-baselines.json`
- `model-risk-exceptions.json`

Store these artifacts with the deployment ticket or pilot report.

## Managed Pilot Rehearsal

Use the rehearsal wrapper when validating an external pilot environment:

```bash
AISEC_BASE_URL=https://aisec.internal.example.com \
AISEC_REHEARSAL_ID=pilot-rehearsal-001 \
AISEC_REHEARSAL_DIR=aisec-managed-rehearsals \
  scripts/rehearse-managed-pilot.sh
```

The run directory contains:

- `pre-smoke/`
- `smoke.log`
- `post-smoke/`
- `README.md`

Review checklist:

- `smoke.log` ends with a passing evaluation summary.
- `post-smoke/model-risk-rollup.json` includes at least one evaluation.
- `post-smoke/model-risk-evaluations.json` includes the smoke evaluation.
- `pre-smoke/` and `post-smoke/` are attached to the pilot report.

## Rollback Runbook

Rollback trigger examples:

- `/api/ready/` fails after deployment.
- `scripts/smoke-managed-api.sh` fails against staging or production.
- Existing evaluations, baselines, or exceptions no longer list.
- OpenAPI paths are missing expected model-risk endpoints.
- Error rate or latency exceeds the pilot threshold.

Before rollback, capture failure evidence:

```bash
AISEC_BASE_URL=https://aisec.internal.example.com \
AISEC_EVIDENCE_DIR=aisec-managed-evidence/failed-upgrade \
  scripts/capture-managed-evidence.sh
```

Docker Compose rollback:

```bash
cd deploy
AISEC_IMAGE_TAG=1.10.0 docker compose -f docker-compose.prod.yml up -d
AISEC_BASE_URL=http://localhost:8000 ../scripts/smoke-managed-api.sh
```

Kubernetes rollback:

```bash
kubectl -n aisec rollout undo deploy/aisec-api
kubectl -n aisec rollout status deploy/aisec-api
AISEC_BASE_URL=https://aisec.internal.example.com scripts/smoke-managed-api.sh
```

Helm rollback:

```bash
helm history aisec -n aisec
helm rollback aisec <REVISION> -n aisec
kubectl -n aisec rollout status deploy/aisec-api
AISEC_BASE_URL=https://aisec.internal.example.com scripts/smoke-managed-api.sh
```

After rollback, capture recovery evidence:

```bash
AISEC_BASE_URL=https://aisec.internal.example.com \
AISEC_EVIDENCE_DIR=aisec-managed-evidence/post-rollback \
  scripts/capture-managed-evidence.sh
```

## Current Asset Status

The checked-in Docker Compose, Kubernetes, and Helm assets are aligned with the
current `1.10.0` service image and probes:

- liveness: `/api/live/`
- readiness: `/api/ready/`
- image tag: `ghcr.io/fboiero/aisec:1.10.0`
