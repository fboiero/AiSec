# AiSec Managed Pilot Report Template

Use this template after running `scripts/rehearse-managed-pilot.sh` against a
managed AiSec environment.

## Pilot Summary

| Field | Value |
| --- | --- |
| Pilot name |  |
| Environment | staging / production pilot |
| AiSec base URL |  |
| AiSec image tag |  |
| Rehearsal ID |  |
| Date/time UTC |  |
| Owner |  |
| Reviewer |  |

## Scope

Describe the target integration:

- Orchestrator or platform:
- Adapter mode: CLI / container / HTTP API
- Target use cases:
- Frameworks requested:
- Policy threshold:
- Expected decision: advisory / blocking / baseline regression

## Evidence Package

Attach or link the rehearsal directory:

```text
aisec-managed-rehearsals/<REHEARSAL_ID>/
```

Required artifacts:

- `pre-smoke/live.json`
- `pre-smoke/ready.json`
- `pre-smoke/openapi.json`
- `pre-smoke/model-risk-rollup.json`
- `smoke.log`
- `post-smoke/live.json`
- `post-smoke/ready.json`
- `post-smoke/openapi.json`
- `post-smoke/model-risk-rollup.json`
- `post-smoke/model-risk-evaluations.json`
- `post-smoke/model-risk-baselines.json`
- `post-smoke/model-risk-exceptions.json`

## Smoke Result

| Check | Result | Notes |
| --- | --- | --- |
| `/api/live/` | pass / fail |  |
| `/api/ready/` | pass / fail |  |
| `POST /api/evaluate/model/` | pass / fail |  |
| `GET /api/evaluations/rollup/` | pass / fail |  |
| Evaluation persisted | pass / fail |  |
| `policy_verdict` present | pass / fail |  |

Smoke evaluation:

| Field | Value |
| --- | --- |
| `evaluation_id` |  |
| `request_id` |  |
| `target.name` |  |
| `overall_risk` |  |
| `risk_score` |  |
| `policy_verdict.status` |  |

## Governance Checks

| Check | Result | Notes |
| --- | --- | --- |
| Evaluation history lists successfully | pass / fail |  |
| Rollup returns posture metrics | pass / fail |  |
| Baselines endpoint lists successfully | pass / fail |  |
| Exceptions endpoint lists successfully | pass / fail |  |
| OpenAPI includes model-risk endpoints | pass / fail |  |
| Evidence captures are attached | pass / fail |  |

## Findings And Exceptions

Summarize notable findings:

| Severity | Finding | Frameworks | Action |
| --- | --- | --- | --- |
|  |  |  |  |

Accepted exceptions:

| Fingerprint | Reason | Accepted by | Expiry |
| --- | --- | --- | --- |
|  |  |  |  |

## Rollback Readiness

| Check | Result | Notes |
| --- | --- | --- |
| Previous image tag known | pass / fail |  |
| `/data` backup available | pass / fail |  |
| Rollback command documented | pass / fail |  |
| Failure evidence capture tested | pass / fail |  |
| Post-rollback smoke command documented | pass / fail |  |

Rollback command used or planned:

```bash
# Docker Compose
AISEC_IMAGE_TAG=<previous-tag> docker compose -f deploy/docker-compose.prod.yml up -d

# Kubernetes
kubectl -n aisec rollout undo deploy/aisec-api

# Helm
helm rollback aisec <REVISION> -n aisec
```

## Decision

Decision: go / no-go / continue pilot

Rationale:

- 

Follow-up actions:

| Owner | Action | Due date |
| --- | --- | --- |
|  |  |  |
