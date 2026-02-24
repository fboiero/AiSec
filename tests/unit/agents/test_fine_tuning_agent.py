"""Tests for FineTuningSecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.fine_tuning import (
    DATASET_LOAD_PATTERNS,
    DATASET_VALIDATION_PATTERNS,
    PII_SCRUB_PATTERNS,
    PROVENANCE_PATTERNS,
    REGISTRY_PROTECTION_PATTERNS,
    REGISTRY_PUSH_PATTERNS,
    REPRODUCIBILITY_PATTERNS,
    SECRET_ENV_PATTERNS,
    SECRET_PATTERNS,
    TRAINING_PATTERNS,
    UNTRUSTED_DATA_PATTERNS,
    FineTuningSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestFineTuningMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert FineTuningSecurityAgent.name == "fine_tuning"

    def test_phase(self):
        assert FineTuningSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM03" in FineTuningSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert FineTuningSecurityAgent.depends_on == []


class TestFineTuningPatterns:
    """Test regex pattern matching."""

    def test_training_patterns_match(self):
        assert TRAINING_PATTERNS.search("Trainer(model=model, args=args)")
        assert TRAINING_PATTERNS.search("SFTTrainer(model=model)")

    def test_dataset_load_matches(self):
        assert DATASET_LOAD_PATTERNS.search("load_dataset('imdb')")
        assert DATASET_LOAD_PATTERNS.search("from_csv('data.csv')")

    def test_secret_patterns_match(self):
        assert SECRET_PATTERNS.search("hf_abcdefghijklmnopqrstuvwxyz")
        assert SECRET_PATTERNS.search("sk-abcdefghijklmnopqrstuvwxyz")


class TestFineTuningNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestUnvalidatedTrainingData:
    """Test unvalidated training data detection."""

    def test_detects_unvalidated_data(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        files = {
            "/app/train.py": (
                'from datasets import load_dataset\n'
                'from transformers import Trainer, TrainingArguments\n'
                'dataset = load_dataset("my-org/dataset")\n'
                'trainer = Trainer(model=model, train_dataset=dataset)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unvalidated_data(files, combined)
        findings = [f for f in agent.findings if "Unvalidated" in f.title]
        assert len(findings) >= 1

    def test_validated_data_passes(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        files = {
            "/app/train.py": (
                'from datasets import load_dataset\n'
                'from transformers import Trainer, TrainingArguments\n'
                'dataset = load_dataset("my-org/dataset")\n'
                'dataset = dataset.filter(lambda x: len(x["text"]) > 10)\n'
                'trainer = Trainer(model=model, train_dataset=dataset)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unvalidated_data(files, combined)
        findings = [f for f in agent.findings if "Unvalidated" in f.title]
        assert len(findings) == 0


class TestTrainingPIIExposure:
    """Test training data PII exposure detection."""

    def test_detects_training_pii(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        combined = (
            'from datasets import load_dataset\n'
            'from transformers import Trainer, TrainingArguments\n'
            'dataset = load_dataset("customer-data")\n'
            'args = TrainingArguments(output_dir="./results")\n'
            'trainer = Trainer(model=model, args=args, train_dataset=dataset)\n'
        )
        agent._check_training_pii(combined)
        findings = [f for f in agent.findings if "PII" in f.title]
        assert len(findings) >= 1

    def test_pii_scrubbing_passes(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        combined = (
            'from datasets import load_dataset\n'
            'from transformers import Trainer, TrainingArguments\n'
            'from presidio_analyzer import AnalyzerEngine\n'
            'dataset = load_dataset("customer-data")\n'
            'analyzer = AnalyzerEngine()\n'
            'args = TrainingArguments(output_dir="./results")\n'
            'trainer = Trainer(model=model, args=args)\n'
        )
        agent._check_training_pii(combined)
        findings = [f for f in agent.findings if "PII" in f.title]
        assert len(findings) == 0


class TestTrainingSecrets:
    """Test hardcoded training secrets detection."""

    def test_detects_hardcoded_secrets(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        files = {
            "/app/train.py": (
                'from transformers import Trainer\n'
                'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz"\n'
                'model = AutoModel.from_pretrained("gpt2", token=HF_TOKEN)\n'
            )
        }
        agent._check_training_secrets(files)
        findings = [f for f in agent.findings if "secrets" in f.title.lower() or "Secrets" in f.title]
        assert len(findings) >= 1

    def test_secrets_from_env_passes(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        files = {
            "/app/train.py": (
                'import os\n'
                'from transformers import Trainer\n'
                'HF_TOKEN = os.environ["HF_TOKEN"]\n'
                'model = AutoModel.from_pretrained("gpt2", token=HF_TOKEN)\n'
            )
        }
        agent._check_training_secrets(files)
        findings = [f for f in agent.findings if "secrets" in f.title.lower() or "Secrets" in f.title]
        assert len(findings) == 0


class TestNoProvenance:
    """Test missing training provenance detection."""

    def test_detects_no_provenance(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        combined = (
            'from transformers import Trainer, TrainingArguments\n'
            'args = TrainingArguments(output_dir="./results")\n'
            'trainer = Trainer(model=model, args=args)\n'
            'trainer.train()\n'
        )
        agent._check_no_provenance(combined)
        findings = [f for f in agent.findings if "provenance" in f.title.lower()]
        assert len(findings) >= 1


class TestUnprotectedRegistry:
    """Test unprotected model registry push detection."""

    def test_detects_unprotected_push(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        files = {
            "/app/publish.py": (
                'from transformers import Trainer\n'
                'trainer = Trainer(model=model)\n'
                'trainer.push_to_hub("my-model")\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unprotected_registry(files, combined)
        findings = [f for f in agent.findings if "registry" in f.title.lower()]
        assert len(findings) >= 1


class TestUntrustedTrainingData:
    """Test untrusted web-scraped training data detection."""

    def test_detects_untrusted_data(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        combined = (
            'from transformers import Trainer\n'
            'training_data = BeautifulSoup(html).get_text() # scraped training data\n'
            'trainer = Trainer(model=model, train_dataset=data)\n'
        )
        agent._check_untrusted_data(combined)
        findings = [f for f in agent.findings if "untrusted" in f.title.lower()]
        assert len(findings) >= 1


class TestNoReproducibility:
    """Test missing training reproducibility detection."""

    def test_detects_no_reproducibility(self, scan_context):
        agent = FineTuningSecurityAgent(scan_context)
        combined = (
            'from transformers import Trainer, TrainingArguments\n'
            'args = TrainingArguments(output_dir="./results")\n'
            'trainer = Trainer(model=model, args=args)\n'
            'trainer.train()\n'
        )
        agent._check_no_reproducibility(combined)
        findings = [f for f in agent.findings if "reproducibility" in f.title.lower()]
        assert len(findings) >= 1
