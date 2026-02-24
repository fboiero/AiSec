"""Tests for deployment manifests validity (v1.7.0)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

DEPLOY_DIR = Path(__file__).resolve().parent.parent.parent / "deploy"
K8S_DIR = DEPLOY_DIR / "kubernetes"
HELM_DIR = DEPLOY_DIR / "helm" / "aisec"


class TestKubernetesManifests:
    """Validate Kubernetes YAML manifests."""

    @pytest.mark.parametrize("filename", [
        "deployment.yaml",
        "service.yaml",
        "configmap.yaml",
        "secret.yaml",
        "ingress.yaml",
        "pvc.yaml",
        "rbac.yaml",
    ])
    def test_k8s_manifest_is_valid_yaml(self, filename):
        path = K8S_DIR / filename
        assert path.exists(), f"{filename} does not exist"
        with open(path) as f:
            docs = list(yaml.safe_load_all(f))
        assert len(docs) >= 1
        for doc in docs:
            assert isinstance(doc, dict)
            assert "apiVersion" in doc
            assert "kind" in doc
            assert "metadata" in doc

    def test_deployment_has_replicas(self):
        with open(K8S_DIR / "deployment.yaml") as f:
            doc = yaml.safe_load(f)
        assert doc["spec"]["replicas"] >= 1

    def test_deployment_has_health_probes(self):
        with open(K8S_DIR / "deployment.yaml") as f:
            doc = yaml.safe_load(f)
        container = doc["spec"]["template"]["spec"]["containers"][0]
        assert "livenessProbe" in container
        assert "readinessProbe" in container

    def test_service_port_8000(self):
        with open(K8S_DIR / "service.yaml") as f:
            doc = yaml.safe_load(f)
        assert doc["spec"]["ports"][0]["port"] == 8000

    def test_secret_has_placeholder(self):
        with open(K8S_DIR / "secret.yaml") as f:
            doc = yaml.safe_load(f)
        assert "AISEC_SECRET_KEY" in doc["stringData"]

    def test_rbac_has_service_account(self):
        with open(K8S_DIR / "rbac.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        kinds = [d["kind"] for d in docs]
        assert "ServiceAccount" in kinds
        assert "Role" in kinds
        assert "RoleBinding" in kinds


class TestHelmChart:
    """Validate Helm chart structure."""

    def test_chart_yaml_exists(self):
        path = HELM_DIR / "Chart.yaml"
        assert path.exists()
        with open(path) as f:
            chart = yaml.safe_load(f)
        assert chart["name"] == "aisec"
        assert chart["version"] == "1.7.0"
        assert chart["appVersion"] == "1.7.0"

    def test_values_yaml_exists(self):
        path = HELM_DIR / "values.yaml"
        assert path.exists()
        with open(path) as f:
            values = yaml.safe_load(f)
        assert values["replicaCount"] >= 1
        assert "image" in values
        assert "service" in values
        assert "resources" in values

    def test_templates_exist(self):
        templates_dir = HELM_DIR / "templates"
        assert templates_dir.exists()
        expected = ["deployment.yaml", "service.yaml", "configmap.yaml", "_helpers.tpl"]
        for name in expected:
            assert (templates_dir / name).exists(), f"Template {name} missing"

    def test_helpers_tpl_has_definitions(self):
        path = HELM_DIR / "templates" / "_helpers.tpl"
        content = path.read_text()
        assert "aisec.fullname" in content
        assert "aisec.labels" in content
        assert "aisec.selectorLabels" in content


class TestDockerCompose:
    """Validate docker-compose.prod.yml."""

    def test_docker_compose_valid_yaml(self):
        path = DEPLOY_DIR / "docker-compose.prod.yml"
        assert path.exists()
        with open(path) as f:
            doc = yaml.safe_load(f)
        assert "services" in doc

    def test_docker_compose_has_aisec_service(self):
        with open(DEPLOY_DIR / "docker-compose.prod.yml") as f:
            doc = yaml.safe_load(f)
        assert "aisec-api" in doc["services"]
        assert "nginx" in doc["services"]

    def test_docker_compose_port_mapping(self):
        with open(DEPLOY_DIR / "docker-compose.prod.yml") as f:
            doc = yaml.safe_load(f)
        api_service = doc["services"]["aisec-api"]
        assert "8000:8000" in api_service["ports"]

    def test_docker_compose_healthcheck(self):
        with open(DEPLOY_DIR / "docker-compose.prod.yml") as f:
            doc = yaml.safe_load(f)
        api_service = doc["services"]["aisec-api"]
        assert "healthcheck" in api_service
