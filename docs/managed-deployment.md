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
- Baseline creation and comparison work for one approved target.
- Exception creation and expiry behavior are tested.
- Persistent volume survives pod restart.
- Logs include enough context to correlate request failures.
- Backup and restore procedure for `/data` is documented.

## Upgrade Path

1. Deploy the new image tag into staging.
2. Run the two validated OrchestAI use cases.
3. Verify `/api/schema/` for expected paths.
4. Confirm existing evaluations, baselines, and exceptions still list.
5. Promote to production with a rolling update.
6. Keep the previous image tag available for rollback.

## Current Asset Status

The checked-in Docker Compose, Kubernetes, and Helm assets are aligned with the
current `1.10.0` service image and probes:

- liveness: `/api/live/`
- readiness: `/api/ready/`
- image tag: `ghcr.io/fboiero/aisec:1.10.0`
