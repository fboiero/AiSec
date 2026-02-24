# AiSec Deployment Guide

## Quick Start

### Docker Compose (simplest)

```bash
cd deploy/
docker compose -f docker-compose.prod.yml up -d
```

Open `http://localhost:8000/dashboard/` to access the web UI.

### Kubernetes (raw manifests)

```bash
# Create namespace
kubectl create namespace aisec

# Edit secrets first!
vim deploy/kubernetes/secret.yaml

# Apply all manifests
kubectl apply -n aisec -f deploy/kubernetes/

# Verify
kubectl get pods -n aisec
```

### Helm

```bash
# Install with defaults
helm install aisec deploy/helm/aisec/ -n aisec --create-namespace

# Install with custom values
helm install aisec deploy/helm/aisec/ -n aisec --create-namespace \
  --set config.falcoEnabled=true \
  --set config.cloudStorageBackend=s3 \
  --set config.cloudStorageBucket=my-aisec-reports \
  --set secrets.secretKey=$(openssl rand -hex 32)

# Upgrade
helm upgrade aisec deploy/helm/aisec/ -n aisec

# Lint
helm lint deploy/helm/aisec/
```

## Cloud Storage Configuration

Upload scan reports to cloud storage automatically:

### Amazon S3

```bash
export AISEC_CLOUD_STORAGE_BACKEND=s3
export AISEC_CLOUD_STORAGE_BUCKET=my-aisec-reports
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
aisec scan myapp:latest --cloud-storage
```

### Google Cloud Storage

```bash
export AISEC_CLOUD_STORAGE_BACKEND=gcs
export AISEC_CLOUD_STORAGE_BUCKET=my-aisec-reports
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
aisec scan myapp:latest --cloud-storage
```

### Azure Blob Storage

```bash
export AISEC_CLOUD_STORAGE_BACKEND=azure
export AISEC_CLOUD_STORAGE_BUCKET=my-container
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=..."
aisec scan myapp:latest --cloud-storage
```

## Falco Runtime Monitoring

Enable Falco sidecar for eBPF-based syscall monitoring:

```bash
# Via environment
export AISEC_FALCO_ENABLED=true
aisec scan myapp:latest

# Via Helm
helm install aisec deploy/helm/aisec/ --set config.falcoEnabled=true
```

Requires Docker socket access and the `falcosecurity/falco-no-driver` image.

## Architecture

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Nginx   │────▶│  AiSec API   │────▶│  SQLite DB   │
│ (reverse │     │  (port 8000) │     │  (/data/)    │
│  proxy)  │     │  + Dashboard │     └──────────────┘
└──────────┘     └──────┬───────┘
                        │
                  ┌─────▼──────┐     ┌──────────────┐
                  │   Docker   │────▶│   Cloud      │
                  │   Socket   │     │   Storage    │
                  │            │     │  (S3/GCS/Az) │
                  └────────────┘     └──────────────┘
```
