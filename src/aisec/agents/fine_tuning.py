"""Fine-tuning pipeline security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Training framework patterns
TRAINING_PATTERNS = re.compile(
    r'(?:Trainer|SFTTrainer|DPOTrainer|PPOTrainer|RewardTrainer|'
    r'TrainingArguments|Seq2SeqTrainer|Seq2SeqTrainingArguments|'
    r'model\.fit|model\.train|fine_tune|finetune|'
    r'FineTuningJob|create_fine_tuning_job|'
    r'AutoModelForCausalLM.*from_pretrained|'
    r'prepare_model_for_kbit_training|get_peft_model)',
    re.IGNORECASE,
)

# Dataset loading patterns
DATASET_LOAD_PATTERNS = re.compile(
    r'(?:load_dataset|from_csv|from_json|from_parquet|'
    r'read_parquet|read_csv|read_json|from_pandas|'
    r'from_text|from_dict|DatasetDict|'
    r'Dataset\.from_|IterableDataset)',
)

# Dataset validation / filtering patterns
DATASET_VALIDATION_PATTERNS = re.compile(
    r'(?:filter\s*\(|validate.*data|data.*validate|'
    r'clean.*data|data.*clean|quality.*check|'
    r'decontaminate|data_quality|check_data|'
    r'assert.*len|schema.*validate)',
    re.IGNORECASE,
)

# PII scrubbing patterns
PII_SCRUB_PATTERNS = re.compile(
    r'(?:scrub_pii|anonymize|presidio|redact|mask_pii|'
    r'pii_filter|remove_pii|sanitize_pii|'
    r'AnalyzerEngine|AnonymizerEngine|'
    r'pii_detect|strip_pii|clean_pii|'
    r'de_identify|deidentify)',
    re.IGNORECASE,
)

# Data deduplication patterns
DEDUP_PATTERNS = re.compile(
    r'(?:dedup|deduplicate|drop_duplicates|unique|'
    r'minhash|simhash|near_dedup|exact_dedup|'
    r'remove_duplicates|deduplication)',
    re.IGNORECASE,
)

# Checkpoint / model save patterns
CHECKPOINT_SAVE_PATTERNS = re.compile(
    r'(?:save_pretrained|save_model|save_checkpoint|'
    r'torch\.save|model\.save|save_weights|'
    r'output_dir|checkpoint_dir)',
)

# Insecure checkpoint locations
INSECURE_CHECKPOINT_PATTERNS = re.compile(
    r'(?:save_pretrained|save_model|save_checkpoint|'
    r'torch\.save|output_dir)\s*[\(=]\s*["\'](?:/tmp|/var/tmp|/dev/shm)',
)

# Checkpoint encryption / protection patterns
CHECKPOINT_PROTECTION_PATTERNS = re.compile(
    r'(?:encrypt.*checkpoint|checkpoint.*encrypt|'
    r'signed.*model|model.*sign|checksum.*model|'
    r'model.*checksum|hmac.*model|model.*hmac|'
    r'kms.*model|vault.*model|encrypted_save)',
    re.IGNORECASE,
)

# Secret / API key patterns in training scripts
SECRET_PATTERNS = re.compile(
    r'(?:hf_[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{20,}|'
    r'sk-proj-[a-zA-Z0-9]{20,}|'
    r'wandb_[a-zA-Z0-9]{20,}|'
    r'AKIA[0-9A-Z]{16}|'
    r'xoxb-[0-9]{10,}|'
    r'ghp_[a-zA-Z0-9]{36}|'
    r'glpat-[a-zA-Z0-9\-]{20,})',
)

# Secret from env (safe pattern)
SECRET_ENV_PATTERNS = re.compile(
    r'(?:os\.environ|os\.getenv|settings\.|config\.|'
    r'HfFolder\.get_token|login\(\)|notebook_login)',
)

# Data provenance / tracking patterns
PROVENANCE_PATTERNS = re.compile(
    r'(?:dvc|mlflow|wandb\.init|wandb\.log|clearml|'
    r'neptune|comet|tensorboard|aim\.Run|'
    r'experiment_tracker|data_version|mlrun)',
    re.IGNORECASE,
)

# RLHF reward hacking patterns
REWARD_HACK_PATTERNS = re.compile(
    r'(?:reward.*len\(|reward.*length|'
    r'len\(response\).*reward|'
    r'reward.*\.count|'
    r'reward.*keyword|keyword.*reward|'
    r'reward\s*=\s*len\(|'
    r'reward\s*=\s*float\(len)',
    re.IGNORECASE,
)

# Proper reward model patterns
PROPER_REWARD_PATTERNS = re.compile(
    r'(?:RewardModel|AutoModelForSequenceClassification|'
    r'reward_model|preference_model|human_feedback|'
    r'PPOTrainer.*reward_model|DPOTrainer)',
    re.IGNORECASE,
)

# Model registry push patterns
REGISTRY_PUSH_PATTERNS = re.compile(
    r'(?:push_to_hub|upload_model|publish_model|'
    r'register_model|deploy_model|model_registry)',
)

# Registry protection patterns
REGISTRY_PROTECTION_PATTERNS = re.compile(
    r'(?:private\s*=\s*True|sign|cosign|sigstore|'
    r'verify_model|model_card|gated\s*=\s*True|'
    r'access_token|token\s*=)',
    re.IGNORECASE,
)

# Untrusted data source patterns (web scraping to training)
UNTRUSTED_DATA_PATTERNS = re.compile(
    r'(?:requests\.get.*(?:train|dataset|data)|'
    r'BeautifulSoup.*(?:train|data)|'
    r'scrapy.*(?:train|data)|'
    r'wget.*(?:train|data)|'
    r'curl.*(?:train|data)|'
    r'urlopen.*(?:train|data)|'
    r'web_scrape|scrape.*data|crawl.*data)',
    re.IGNORECASE,
)

# Data filtering / cleaning for untrusted sources
DATA_FILTER_PATTERNS = re.compile(
    r'(?:content_filter|toxicity|profanity|'
    r'data_cleaning|clean_text|filter_toxic|'
    r'quality_filter|moderation|safety_filter|'
    r'nsfw_filter|hate_speech)',
    re.IGNORECASE,
)

# Reproducibility patterns
REPRODUCIBILITY_PATTERNS = re.compile(
    r'(?:seed|random_state|set_seed|manual_seed|'
    r'torch\.manual_seed|np\.random\.seed|'
    r'random\.seed|deterministic|'
    r'config.*version|training_config)',
    re.IGNORECASE,
)


class FineTuningSecurityAgent(BaseAgent):
    """Audits fine-tuning pipelines for security risks."""

    name: ClassVar[str] = "fine_tuning"
    description: ClassVar[str] = (
        "Audits fine-tuning pipelines: unvalidated training data, PII "
        "exposure, poisoned datasets, checkpoint security, training "
        "secrets, data provenance, RLHF reward hacking, and model "
        "registry protection."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "LLM04"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze fine-tuning pipeline security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for fine-tuning analysis",
                description="No source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        # Only run checks if training patterns are detected
        has_training = bool(TRAINING_PATTERNS.search(combined))
        if not has_training:
            return

        self._check_unvalidated_data(all_content, combined)
        self._check_training_pii(combined)
        self._check_no_deduplication(combined)
        self._check_unsafe_checkpoints(all_content)
        self._check_training_secrets(all_content)
        self._check_no_provenance(combined)
        self._check_reward_hacking(combined)
        self._check_unprotected_registry(all_content, combined)
        self._check_untrusted_data(combined)
        self._check_no_reproducibility(combined)

    def _check_unvalidated_data(self, files: dict[str, str], combined: str) -> None:
        """Check for dataset loading without validation steps."""
        for fpath, content in files.items():
            load_matches = list(DATASET_LOAD_PATTERNS.finditer(content))
            if not load_matches:
                continue

            has_validation = bool(DATASET_VALIDATION_PATTERNS.search(content))
            if not has_validation:
                lines = [str(content[:m.start()].count("\n") + 1) for m in load_matches]
                self.add_finding(
                    title="Unvalidated training data sources",
                    description=(
                        f"Dataset loaded at {fpath} (lines: {', '.join(lines)}) "
                        "without validation, filtering, or quality checks. "
                        "Unvalidated training data can contain poisoned samples, "
                        "adversarial examples, or corrupted records."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM03", "LLM04"],
                    nist_ai_rmf=["GOVERN", "MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unvalidated dataset loading at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add data validation after loading: check schema, filter "
                        "outliers, validate content quality. Use dataset.filter() "
                        "or implement custom validation functions."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.5,
                )

    def _check_training_pii(self, combined: str) -> None:
        """Check for missing PII scrubbing before training."""
        has_dataset_load = bool(DATASET_LOAD_PATTERNS.search(combined))
        has_training = bool(TRAINING_PATTERNS.search(combined))
        has_pii_scrub = bool(PII_SCRUB_PATTERNS.search(combined))

        if has_dataset_load and has_training and not has_pii_scrub:
            self.add_finding(
                title="Training data PII exposure",
                description=(
                    "Training pipeline loads data and trains models without PII "
                    "detection or scrubbing. Models trained on PII can memorize "
                    "and reproduce personal data during inference, violating "
                    "privacy regulations (GDPR, CCPA)."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM04"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                remediation=(
                    "Add PII scrubbing to the data pipeline before training: use "
                    "Presidio, spaCy NER, or regex-based PII detection. Implement "
                    "differential privacy with Opacus or TensorFlow Privacy."
                ),
                cvss_score=7.0,
                ai_risk_score=8.0,
            )

    def _check_no_deduplication(self, combined: str) -> None:
        """Check for missing data deduplication (memorization risk)."""
        has_dataset_load = bool(DATASET_LOAD_PATTERNS.search(combined))
        has_training = bool(TRAINING_PATTERNS.search(combined))
        has_dedup = bool(DEDUP_PATTERNS.search(combined))

        if has_dataset_load and has_training and not has_dedup:
            self.add_finding(
                title="No training data deduplication",
                description=(
                    "Training data is loaded without deduplication. Duplicate "
                    "samples increase memorization risk — the model is more "
                    "likely to reproduce training data verbatim during inference, "
                    "potentially leaking sensitive content."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM04"],
                nist_ai_rmf=["MEASURE"],
                remediation=(
                    "Deduplicate training data using exact or near-duplicate "
                    "detection (MinHash, SimHash). Use dataset.unique() or "
                    "implement custom deduplication before training."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_unsafe_checkpoints(self, files: dict[str, str]) -> None:
        """Check for model checkpoints saved to insecure locations."""
        for fpath, content in files.items():
            insecure_matches = list(INSECURE_CHECKPOINT_PATTERNS.finditer(content))
            if not insecure_matches:
                continue

            has_protection = bool(CHECKPOINT_PROTECTION_PATTERNS.search(content))
            if not has_protection:
                lines = [str(content[:m.start()].count("\n") + 1) for m in insecure_matches]
                self.add_finding(
                    title="Unsafe model checkpoint storage",
                    description=(
                        f"Model checkpoint saved to insecure location at {fpath} "
                        f"(lines: {', '.join(lines)}) — likely /tmp or world-readable "
                        "directory without encryption. Checkpoints contain full model "
                        "weights and can be stolen or tampered with."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM03"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Insecure checkpoint at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Save checkpoints to a secure, encrypted location with "
                        "restricted permissions. Use signed checksums to verify "
                        "checkpoint integrity before loading."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_training_secrets(self, files: dict[str, str]) -> None:
        """Check for hardcoded secrets in training scripts."""
        for fpath, content in files.items():
            secret_matches = list(SECRET_PATTERNS.finditer(content))
            if not secret_matches:
                continue

            for match in secret_matches:
                # Check if the secret comes from environment (safe)
                context_start = max(0, match.start() - 120)
                context = content[context_start:match.end()]
                if SECRET_ENV_PATTERNS.search(context):
                    continue

                line = content[:match.start()].count("\n") + 1
                # Redact the secret for the finding
                secret_preview = match.group()[:8] + "..." + match.group()[-4:]
                self.add_finding(
                    title="Training secrets exposure in source code",
                    description=(
                        f"Hardcoded secret at {fpath} (line {line}): "
                        f"{secret_preview}. API keys, tokens, or credentials "
                        "in training scripts can be extracted from containers, "
                        "git history, or model artifacts."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_llm=["LLM03"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Hardcoded secret at {fpath}",
                        raw_data=f"Line: {line}, prefix: {match.group()[:8]}...",
                        location=fpath,
                    )],
                    remediation=(
                        "Use environment variables or secret managers: "
                        "os.environ['HF_TOKEN']. Never commit API keys to source "
                        "code. Use HfFolder.get_token() or huggingface_hub.login()."
                    ),
                    cvss_score=9.0,
                    ai_risk_score=8.0,
                )

    def _check_no_provenance(self, combined: str) -> None:
        """Check for missing training data provenance tracking."""
        has_training = bool(TRAINING_PATTERNS.search(combined))
        has_provenance = bool(PROVENANCE_PATTERNS.search(combined))

        if has_training and not has_provenance:
            self.add_finding(
                title="No training data provenance tracking",
                description=(
                    "Training pipeline has no experiment tracking or data versioning "
                    "(no DVC, MLflow, W&B, or similar). Without provenance, it is "
                    "impossible to audit what data was used, detect poisoning, or "
                    "reproduce training runs."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03", "LLM04"],
                nist_ai_rmf=["GOVERN", "MAP"],
                remediation=(
                    "Add experiment tracking with MLflow, Weights & Biases, or "
                    "ClearML. Version training data with DVC. Log dataset hashes, "
                    "hyperparameters, and training metrics."
                ),
                cvss_score=4.0,
                ai_risk_score=5.0,
            )

    def _check_reward_hacking(self, combined: str) -> None:
        """Check for RLHF reward hacking patterns."""
        has_reward_hack = bool(REWARD_HACK_PATTERNS.search(combined))
        has_proper_reward = bool(PROPER_REWARD_PATTERNS.search(combined))

        if has_reward_hack and not has_proper_reward:
            self.add_finding(
                title="RLHF reward hacking patterns detected",
                description=(
                    "Reward function appears to use simple heuristics like "
                    "response length or keyword matching instead of a trained "
                    "reward model. This enables reward hacking where the model "
                    "optimizes for the proxy metric rather than actual quality."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM04"],
                nist_ai_rmf=["MEASURE"],
                remediation=(
                    "Use a trained reward model (AutoModelForSequenceClassification) "
                    "instead of heuristic rewards. Implement reward model ensembles "
                    "and constrained optimization to mitigate reward hacking."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_unprotected_registry(self, files: dict[str, str], combined: str) -> None:
        """Check for model pushes without privacy/signing."""
        for fpath, content in files.items():
            push_matches = list(REGISTRY_PUSH_PATTERNS.finditer(content))
            if not push_matches:
                continue

            has_protection = bool(REGISTRY_PROTECTION_PATTERNS.search(content))
            if not has_protection:
                lines = [str(content[:m.start()].count("\n") + 1) for m in push_matches]
                self.add_finding(
                    title="Unprotected model registry push",
                    description=(
                        f"Model pushed to registry at {fpath} (lines: "
                        f"{', '.join(lines)}) without private=True, signing, or "
                        "access controls. Public model uploads expose proprietary "
                        "weights and may include memorized training data."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM03"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unprotected registry push at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use push_to_hub(private=True) for proprietary models. "
                        "Sign model artifacts with cosign/sigstore. Add model cards "
                        "with training data documentation."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_untrusted_data(self, combined: str) -> None:
        """Check for web-scraped data piped directly to training."""
        has_untrusted = bool(UNTRUSTED_DATA_PATTERNS.search(combined))
        has_training = bool(TRAINING_PATTERNS.search(combined))
        has_filter = bool(DATA_FILTER_PATTERNS.search(combined))

        if has_untrusted and has_training and not has_filter:
            self.add_finding(
                title="Training on untrusted web-scraped data",
                description=(
                    "Web-scraped data appears to flow into the training pipeline "
                    "without content filtering or quality checks. Untrusted data "
                    "from the web can contain adversarial examples, toxic content, "
                    "or data poisoning payloads."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM03", "LLM04"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                remediation=(
                    "Add content filtering for web-scraped data: toxicity detection, "
                    "quality scoring, and deduplication. Use curated datasets or "
                    "implement manual review for training data from untrusted sources."
                ),
                cvss_score=8.0,
                ai_risk_score=9.0,
            )

    def _check_no_reproducibility(self, combined: str) -> None:
        """Check for missing training reproducibility controls."""
        has_training = bool(TRAINING_PATTERNS.search(combined))
        has_reproducibility = bool(REPRODUCIBILITY_PATTERNS.search(combined))

        if has_training and not has_reproducibility:
            self.add_finding(
                title="No training reproducibility controls",
                description=(
                    "Training pipeline has no random seed setting or configuration "
                    "versioning. Without reproducibility, training runs cannot be "
                    "audited, compared, or debugged — making it impossible to verify "
                    "that a model was trained on clean data."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM04"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Set random seeds: set_seed(42) or torch.manual_seed(42). "
                    "Version training configs with git or DVC. Log all "
                    "hyperparameters to experiment tracker."
                ),
                cvss_score=3.0,
                ai_risk_score=4.0,
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect Python, YAML, and JSON config files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f "
            "\\( -name '*.py' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' \\) "
            "-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _read_file(self, fpath: str) -> str:
        """Read a file from the container."""
        cid = self.context.container_id
        if not cid:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "head", "-c", "65536", fpath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return ""
            return stdout.decode(errors="replace")
        except Exception:
            return ""
