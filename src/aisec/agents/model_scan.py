"""AI model file security analysis agent.

Scans for malicious serialization payloads (pickle exploits), verifies model
provenance and integrity, checks file permissions, and recommends safe
serialization formats such as safetensors.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model file extensions recognised by this agent
# ---------------------------------------------------------------------------

MODEL_FILE_EXTENSIONS: set[str] = {
    ".pkl", ".pickle",          # Python pickle
    ".pt", ".pth",              # PyTorch
    ".h5", ".hdf5",             # Keras / HDF5
    ".onnx",                    # ONNX
    ".safetensors",             # Safetensors (safe)
    ".bin",                     # Generic binary / HuggingFace
    ".joblib",                  # Joblib (pickle-based)
    ".npy", ".npz",             # NumPy
    ".pb",                      # TensorFlow protobuf
    ".tflite",                  # TensorFlow Lite
    ".gguf", ".ggml",           # llama.cpp quantised formats
}

# ---------------------------------------------------------------------------
# Dangerous pickle opcodes that can indicate code execution
# ---------------------------------------------------------------------------

DANGEROUS_PICKLE_OPCODES: dict[str, str] = {
    "REDUCE":  r"\x52",         # R  – call a callable with args
    "BUILD":   r"\x62",         # b  – call __setstate__ or __dict__.update
    "GLOBAL":  r"\x63",         # c  – push a global (module.attr)
    "INST":    r"\x69",         # i  – build & push a class instance
    "OBJ":     r"\x6f",         # o  – build a class instance
    "NEWOBJ":  r"\x81",         # protocol 2 – cls.__new__(cls, *args)
    "STACK_GLOBAL": r"\x93",    # protocol 4 – push a global via stack
}

# ---------------------------------------------------------------------------
# Patterns for unsafe model-loading calls in Python source code
# ---------------------------------------------------------------------------

UNSAFE_LOAD_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)"),
        "torch.load() without weights_only=True",
        "Use torch.load(..., weights_only=True) or migrate to safetensors.",
    ),
    (
        re.compile(r"pickle\.load\s*\("),
        "pickle.load() on potentially untrusted data",
        "Avoid pickle.load on untrusted files. Use safetensors, JSON, or "
        "MessagePack for model artifacts.",
    ),
    (
        re.compile(r"joblib\.load\s*\("),
        "joblib.load() on potentially untrusted data",
        "joblib uses pickle internally. Validate provenance before loading, "
        "or convert models to a safe format.",
    ),
    (
        re.compile(
            r"tf\.keras\.models\.load_model\s*\([^)]*custom_objects\s*="
        ),
        "tf.keras.models.load_model() with custom_objects",
        "Custom objects can execute arbitrary code during deserialization. "
        "Audit all custom_objects and prefer SavedModel format with signatures.",
    ),
    (
        re.compile(r"pickle\.loads\s*\("),
        "pickle.loads() on potentially untrusted bytes",
        "Never unpickle untrusted data. Use a safe serialization format.",
    ),
    (
        re.compile(r"dill\.load\s*\("),
        "dill.load() can execute arbitrary code",
        "dill extends pickle and is equally dangerous on untrusted data.",
    ),
    (
        re.compile(r"cloudpickle\.load\s*\("),
        "cloudpickle.load() can execute arbitrary code",
        "cloudpickle extends pickle and is equally dangerous on untrusted data.",
    ),
]


class ModelScanAgent(BaseAgent):
    """Scan AI model files for malicious payloads, provenance, and permissions."""

    name: ClassVar[str] = "model_scan"
    description: ClassVar[str] = (
        "Scans AI model files for malicious serialization payloads, backdoor "
        "triggers, provenance integrity, and unsafe file permissions."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "LLM04", "ASI04"]
    depends_on: ClassVar[list[str]] = ["supply_chain"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all model-file security checks."""
        model_files = await self._check_model_files()

        if model_files:
            await self._check_pickle_safety(model_files)
            await self._check_model_provenance(model_files)
            await self._check_model_permissions(model_files)
            await self._check_safetensors_preference(model_files)
            await self._check_model_size_anomaly(model_files)

        # Source-code analysis does not require model files on disk.
        await self._check_model_loading_code()

    # ------------------------------------------------------------------
    # Container exec helper
    # ------------------------------------------------------------------

    async def _exec_in_container(self, command: str) -> str:
        """Run a shell command inside the target container and return stdout."""
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # 1. Model file inventory
    # ------------------------------------------------------------------

    async def _check_model_files(self) -> list[str]:
        """Locate model files inside the container and report an inventory."""
        cid = self.context.container_id
        if not cid:
            return []

        ext_clauses = " -o ".join(
            f"-name '*{ext}'" for ext in sorted(MODEL_FILE_EXTENSIONS)
        )
        raw = await self._exec_in_container(
            f"find / -maxdepth 8 -type f \\( {ext_clauses} \\) "
            "-not -path '/proc/*' -not -path '/sys/*' "
            "-not -path '/dev/*' 2>/dev/null | head -200"
        )
        if not raw:
            return []

        model_files = [p.strip() for p in raw.splitlines() if p.strip()]
        if not model_files:
            return []

        self.add_finding(
            title=f"AI model file inventory ({len(model_files)} files)",
            description=(
                f"Discovered {len(model_files)} model file(s) inside the container. "
                "These files will be inspected for serialization safety, provenance, "
                "and permission issues."
            ),
            severity=Severity.INFO,
            owasp_llm=["LLM03", "LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MAP"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"{len(model_files)} model files found",
                    raw_data="\n".join(f"  {f}" for f in model_files[:50]),
                    location=f"container:{cid}",
                )
            ],
            remediation="Maintain an up-to-date inventory of all model artifacts.",
        )

        # Stash in context for downstream agents.
        self.context.metadata.setdefault("model_files", model_files)
        return model_files

    # ------------------------------------------------------------------
    # 2. Pickle safety analysis
    # ------------------------------------------------------------------

    async def _check_pickle_safety(self, model_files: list[str]) -> None:
        """Scan pickle-based model files for dangerous opcodes and payloads."""
        cid = self.context.container_id
        if not cid:
            return

        pickle_exts = {".pkl", ".pickle", ".pt", ".pth"}
        pickle_files = [f for f in model_files if any(f.endswith(e) for e in pickle_exts)]
        if not pickle_files:
            return

        # ----- Attempt modelscan library first ----------------------------
        modelscan_available = await self._exec_in_container(
            "python3 -c 'from modelscan.modelscan import ModelScan; print(1)' 2>/dev/null"
        )
        if modelscan_available == "1":
            await self._run_modelscan(pickle_files)
            return

        # ----- Fallback: manual opcode analysis ---------------------------
        dangerous_files: list[tuple[str, list[str]]] = []

        for fpath in pickle_files:
            # Read first 64 KB of binary content as hex for opcode inspection
            hex_dump = await self._exec_in_container(
                f"xxd -l 65536 -p '{fpath}' 2>/dev/null"
            )
            if not hex_dump:
                continue

            found_opcodes: list[str] = []
            for opcode_name, opcode_hex in DANGEROUS_PICKLE_OPCODES.items():
                # opcode_hex is like r"\x52" -- extract the hex pair
                hex_pair = opcode_hex.replace(r"\x", "")
                if hex_pair in hex_dump:
                    found_opcodes.append(opcode_name)

            # Additionally grep for known exploit strings in the binary
            exploit_check = await self._exec_in_container(
                f"strings '{fpath}' 2>/dev/null | "
                "grep -i -E 'os\\.system|subprocess|__import__|exec\\(|eval\\(|"
                "__reduce__|builtins|posix|nt|commands' | head -20"
            )
            if exploit_check:
                found_opcodes.append(f"suspicious_strings({len(exploit_check.splitlines())})")

            if found_opcodes:
                dangerous_files.append((fpath, found_opcodes))

        if not dangerous_files:
            return

        details_lines: list[str] = []
        for fpath, opcodes in dangerous_files:
            details_lines.append(f"  {fpath}: {', '.join(opcodes)}")

        severity = Severity.CRITICAL if any(
            "suspicious_strings" in o or "REDUCE" in o or "GLOBAL" in o
            for _, opcodes in dangerous_files for o in opcodes
        ) else Severity.HIGH

        self.add_finding(
            title=f"Dangerous pickle opcodes in model files ({len(dangerous_files)} files)",
            description=(
                f"Found {len(dangerous_files)} pickle-based model file(s) containing "
                "opcodes that enable arbitrary code execution during deserialization. "
                "An attacker can embed a reverse shell, data exfiltration routine, or "
                "backdoor trigger inside a pickle payload that executes when the model "
                "is loaded with torch.load() or pickle.load()."
            ),
            severity=severity,
            owasp_llm=["LLM03", "LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="Dangerous pickle opcodes detected",
                    raw_data="\n".join(details_lines)[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Convert pickle-based models to the safetensors format, which does "
                "not permit arbitrary code execution. If pickle must be used, scan "
                "files with modelscan (https://github.com/protectai/modelscan) before "
                "loading and always call torch.load(..., weights_only=True)."
            ),
            references=[
                "https://github.com/protectai/modelscan",
                "https://huggingface.co/docs/safetensors/",
                "https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/",
            ],
            cvss_score=9.8 if severity == Severity.CRITICAL else 8.0,
            ai_risk_score=9.5,
        )

    async def _run_modelscan(self, pickle_files: list[str]) -> None:
        """Use the modelscan library inside the container to scan model files."""
        cid = self.context.container_id
        if not cid:
            return

        for fpath in pickle_files[:20]:  # cap to avoid excessive scan time
            result = await self._exec_in_container(
                f"python3 -c \""
                f"from modelscan.modelscan import ModelScan; "
                f"ms = ModelScan(); "
                f"r = ms.scan('{fpath}'); "
                f"issues = r.issues if hasattr(r, 'issues') else []; "
                f"print(len(issues)); "
                f"[print(str(i)[:300]) for i in issues[:10]]"
                f"\" 2>/dev/null"
            )
            if not result:
                continue

            lines = result.strip().splitlines()
            try:
                issue_count = int(lines[0])
            except (ValueError, IndexError):
                continue

            if issue_count > 0:
                detail_text = "\n".join(lines[1:]) if len(lines) > 1 else "See modelscan output."
                self.add_finding(
                    title=f"ModelScan flagged {issue_count} issue(s) in {fpath}",
                    description=(
                        f"The modelscan library detected {issue_count} security "
                        f"issue(s) in '{fpath}'. These may include malicious pickle "
                        "opcodes, code injection payloads, or suspicious serialization "
                        "patterns."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_llm=["LLM03", "LLM04"],
                    owasp_agentic=["ASI04"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"modelscan: {issue_count} issues",
                            raw_data=detail_text[:2000],
                            location=f"container:{cid}:{fpath}",
                        )
                    ],
                    remediation=(
                        "Quarantine the flagged model file and investigate its origin. "
                        "Convert to safetensors format if the model weights are legitimate."
                    ),
                    references=["https://github.com/protectai/modelscan"],
                    cvss_score=9.8,
                    ai_risk_score=9.5,
                )

    # ------------------------------------------------------------------
    # 3. Model provenance
    # ------------------------------------------------------------------

    async def _check_model_provenance(self, model_files: list[str]) -> None:
        """Verify model provenance metadata: model cards, configs, checksums."""
        cid = self.context.container_id
        if not cid:
            return

        # Derive unique directories that contain model files.
        model_dirs: set[str] = set()
        for fpath in model_files:
            last_slash = fpath.rfind("/")
            if last_slash > 0:
                model_dirs.add(fpath[:last_slash])

        if not model_dirs:
            return

        provenance_signals: list[str] = []
        missing_signals: list[str] = []

        # ---- Model card / README ----
        card_found = False
        for mdir in model_dirs:
            check = await self._exec_in_container(
                f"ls '{mdir}/README.md' '{mdir}/model_card.md' "
                f"'{mdir}/MODEL_CARD.md' 2>/dev/null"
            )
            if check:
                card_found = True
                provenance_signals.append(f"Model card: {check.splitlines()[0]}")
                break

        if not card_found:
            missing_signals.append("No model card (README.md / model_card.md) found near model files")

        # ---- HuggingFace config.json ----
        config_found = False
        for mdir in model_dirs:
            cfg_raw = await self._exec_in_container(
                f"cat '{mdir}/config.json' 2>/dev/null | head -100"
            )
            if cfg_raw:
                if any(k in cfg_raw for k in ("model_type", "transformers_version", "architectures")):
                    config_found = True
                    provenance_signals.append(f"HuggingFace config.json in {mdir}")
                    break

        if not config_found:
            missing_signals.append("No HuggingFace config.json with model_type/transformers_version found")

        # ---- Hash verification files ----
        hash_files = await self._exec_in_container(
            "find " + " ".join(f"'{d}'" for d in list(model_dirs)[:20]) +
            " -maxdepth 1 -type f \\( -name '*.sha256' -o -name 'checksums*' "
            "-o -name 'SHA256SUMS' -o -name '*.md5' \\) 2>/dev/null | head -10"
        )
        if hash_files:
            provenance_signals.append(f"Hash files: {hash_files.splitlines()[0]}")
        else:
            missing_signals.append("No hash verification files (.sha256, checksums) found")

        # ---- Model registry references ----
        registry_ref = await self._exec_in_container(
            "grep -r -l -i 'huggingface\\.co\\|modelscope\\.cn\\|hf\\.co' "
            + " ".join(f"'{d}'" for d in list(model_dirs)[:20])
            + " 2>/dev/null | head -5"
        )
        if registry_ref:
            provenance_signals.append("Model registry references found")
        else:
            missing_signals.append("No references to model registries (HuggingFace, ModelScope)")

        if missing_signals:
            has_any = len(provenance_signals) > 0
            severity = Severity.LOW if has_any else Severity.MEDIUM

            details = ""
            if provenance_signals:
                details += "Present:\n" + "\n".join(f"  + {s}" for s in provenance_signals) + "\n"
            details += "Missing:\n" + "\n".join(f"  - {s}" for s in missing_signals)

            self.add_finding(
                title=f"Incomplete model provenance ({len(missing_signals)} gaps)",
                description=(
                    f"Model provenance verification found {len(missing_signals)} "
                    "gap(s). Without proper provenance metadata it is difficult to "
                    "verify the origin, integrity, and licensing of model artifacts. "
                    "This increases the risk of data poisoning and supply chain attacks."
                ),
                severity=severity,
                owasp_llm=["LLM03", "LLM04"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP", "MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Model provenance assessment",
                        raw_data=details[:2000],
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Include a model card (README.md) describing the model's origin, "
                    "training data, intended use, and limitations. Provide a config.json "
                    "with model metadata. Distribute SHA-256 checksums alongside model "
                    "files and verify them before loading. Reference the original model "
                    "registry URL and commit hash."
                ),
                references=[
                    "https://huggingface.co/docs/hub/model-cards",
                    "https://arxiv.org/abs/1810.03993",
                ],
                cvss_score=4.5 if severity == Severity.MEDIUM else 3.0,
                ai_risk_score=5.0,
            )

    # ------------------------------------------------------------------
    # 4. Model file permissions
    # ------------------------------------------------------------------

    async def _check_model_permissions(self, model_files: list[str]) -> None:
        """Flag world-writable model files and ownership anomalies."""
        cid = self.context.container_id
        if not cid:
            return

        issues: list[tuple[str, str]] = []  # (file, issue description)

        # Batch stat to reduce exec calls: get permissions and owner
        file_list = " ".join(f"'{f}'" for f in model_files[:50])
        stat_output = await self._exec_in_container(
            f"stat -c '%a %U %n' {file_list} 2>/dev/null || "
            f"stat -f '%Lp %Su %N' {file_list} 2>/dev/null"
        )
        if not stat_output:
            return

        # Determine container user
        container_user = await self._exec_in_container("whoami 2>/dev/null")

        for line in stat_output.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 3:
                continue
            perms, owner, fpath = parts[0], parts[1], parts[2]

            # World-writable check (octal ends in 2, 3, 6, or 7)
            try:
                mode = int(perms, 8)
                if mode & 0o002:
                    issues.append((fpath, f"World-writable (mode {perms}): risk of tampering"))
            except ValueError:
                pass

            # Root-owned files when container runs as non-root
            if owner == "root" and container_user and container_user != "root":
                issues.append((
                    fpath,
                    f"Owned by root but container runs as '{container_user}'"
                ))

        # Check for model files on writable volumes
        mount_info = await self._exec_in_container(
            "cat /proc/self/mountinfo 2>/dev/null | grep -v 'proc\\|sys\\|cgroup'"
        )
        if mount_info:
            writable_mounts: list[str] = []
            for mline in mount_info.splitlines():
                parts = mline.split()
                # mountinfo fields: ... mount_point ... mount_options ...
                if len(parts) >= 5:
                    mount_point = parts[4]
                    # Check if any model file resides on this mount
                    for fpath in model_files:
                        if fpath.startswith(mount_point) and mount_point != "/":
                            if "rw" in parts[5] if len(parts) > 5 else "":
                                writable_mounts.append(
                                    f"{fpath} on writable mount {mount_point}"
                                )
            for wm in writable_mounts[:10]:
                issues.append((wm.split(" on ")[0], wm))

        if not issues:
            return

        # Determine worst severity
        world_writable = any("World-writable" in desc for _, desc in issues)
        severity = Severity.HIGH if world_writable else Severity.MEDIUM

        details = "\n".join(f"  {fpath}: {desc}" for fpath, desc in issues[:30])
        self.add_finding(
            title=f"Insecure model file permissions ({len(issues)} issues)",
            description=(
                f"Found {len(issues)} permission or ownership issue(s) on model "
                "files. World-writable models can be tampered with by any process "
                "in the container, enabling data poisoning or backdoor injection. "
                "Root-owned files in non-root containers may indicate misconfigured "
                "volume mounts."
            ),
            severity=severity,
            owasp_llm=["LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="config",
                    summary="Model file permission issues",
                    raw_data=details[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Set model files to read-only (chmod 444 or 644). Ensure model "
                "directories are not world-writable. Mount model volumes as "
                "read-only (:ro) in Docker. Use appropriate ownership matching "
                "the container's runtime user."
            ),
            cvss_score=7.5 if world_writable else 5.0,
            ai_risk_score=7.0,
        )

    # ------------------------------------------------------------------
    # 5. Safetensors preference
    # ------------------------------------------------------------------

    async def _check_safetensors_preference(self, model_files: list[str]) -> None:
        """Advise migration from pickle-based formats to safetensors."""
        cid = self.context.container_id
        if not cid:
            return

        pickle_model_exts = {".pt", ".pth"}
        pickle_models = [f for f in model_files if any(f.endswith(e) for e in pickle_model_exts)]
        safetensor_models = [f for f in model_files if f.endswith(".safetensors")]

        if not pickle_models:
            return

        # Check whether safetensors library is installed
        safetensors_installed = await self._exec_in_container(
            "python3 -c 'import safetensors; print(safetensors.__version__)' 2>/dev/null"
        )

        severity = Severity.LOW if safetensor_models else Severity.INFO

        details_parts: list[str] = [
            f"Pickle-based models ({len(pickle_models)}):",
        ]
        for f in pickle_models[:15]:
            details_parts.append(f"  {f}")
        if safetensor_models:
            details_parts.append(f"Safetensors models ({len(safetensor_models)}):")
            for f in safetensor_models[:10]:
                details_parts.append(f"  {f}")
        details_parts.append(
            f"safetensors library: {'installed (' + safetensors_installed + ')' if safetensors_installed else 'NOT installed'}"
        )

        self.add_finding(
            title=f"Pickle-based model format in use ({len(pickle_models)} files)",
            description=(
                f"Found {len(pickle_models)} PyTorch model file(s) using pickle-based "
                "serialization (.pt/.pth). The pickle format permits arbitrary code "
                "execution during deserialization. The safetensors format is a drop-in "
                "replacement that stores only tensor data and cannot execute code."
                + (
                    f" {len(safetensor_models)} safetensors file(s) already exist, "
                    "suggesting a partial migration."
                    if safetensor_models else ""
                )
            ),
            severity=severity,
            owasp_llm=["LLM03", "LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="Pickle vs safetensors inventory",
                    raw_data="\n".join(details_parts)[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Convert PyTorch models to safetensors format:\n"
                "  pip install safetensors\n"
                "  from safetensors.torch import save_file, load_file\n"
                "  save_file(state_dict, 'model.safetensors')\n"
                "For HuggingFace models, pass use_safetensors=True when saving. "
                "After migration, remove the original .pt/.pth files."
            ),
            references=[
                "https://huggingface.co/docs/safetensors/",
                "https://github.com/huggingface/safetensors",
            ],
            cvss_score=None,
            ai_risk_score=4.0,
        )

    # ------------------------------------------------------------------
    # 6. Model size anomaly detection
    # ------------------------------------------------------------------

    async def _check_model_size_anomaly(self, model_files: list[str]) -> None:
        """Flag unusually large or suspiciously small model files."""
        cid = self.context.container_id
        if not cid:
            return

        file_list = " ".join(f"'{f}'" for f in model_files[:50])
        size_output = await self._exec_in_container(
            f"stat -c '%s %n' {file_list} 2>/dev/null || "
            f"stat -f '%z %N' {file_list} 2>/dev/null"
        )
        if not size_output:
            return

        anomalies: list[tuple[str, str]] = []
        ten_gb = 10 * 1024 * 1024 * 1024
        one_kb = 1024
        # Extensions where < 1 KB is suspicious for a real model
        real_model_exts = {".pt", ".pth", ".h5", ".hdf5", ".onnx", ".safetensors", ".bin", ".gguf", ".ggml"}

        for line in size_output.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) < 2:
                continue
            try:
                size = int(parts[0])
            except ValueError:
                continue
            fpath = parts[1]

            if size > ten_gb:
                size_gb = size / (1024 ** 3)
                anomalies.append((fpath, f"Very large: {size_gb:.1f} GB (resource risk)"))

            if size < one_kb and any(fpath.endswith(e) for e in real_model_exts):
                anomalies.append((fpath, f"Suspiciously small: {size} bytes (may be corrupted or trojanized)"))

        if not anomalies:
            return

        details = "\n".join(f"  {fpath}: {desc}" for fpath, desc in anomalies)
        self.add_finding(
            title=f"Model file size anomalies ({len(anomalies)} files)",
            description=(
                f"Detected {len(anomalies)} model file(s) with unusual sizes. "
                "Very large models in small containers may cause out-of-memory "
                "conditions. Extremely small model files may indicate corruption, "
                "placeholder files, or trojanized artifacts that contain only a "
                "malicious payload instead of real weights."
            ),
            severity=Severity.INFO,
            owasp_llm=["LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="Model size anomalies",
                    raw_data=details[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Verify that each model file's size matches the expected value from "
                "the model registry. Investigate any file smaller than 1 KB or larger "
                "than expected. Use SHA-256 checksums to confirm file integrity."
            ),
        )

    # ------------------------------------------------------------------
    # 7. Unsafe model loading code
    # ------------------------------------------------------------------

    async def _check_model_loading_code(self) -> None:
        """Analyse Python source for unsafe model deserialization calls."""
        cid = self.context.container_id
        if not cid:
            return

        # Build a combined grep pattern from UNSAFE_LOAD_PATTERNS descriptions
        grep_patterns = [
            r"torch\.load\s*\(",
            r"pickle\.load\s*\(",
            r"pickle\.loads\s*\(",
            r"joblib\.load\s*\(",
            r"dill\.load\s*\(",
            r"cloudpickle\.load\s*\(",
            r"tf\.keras\.models\.load_model\s*\(",
            r"keras\.models\.load_model\s*\(",
        ]
        grep_expr = "|".join(grep_patterns)

        source_hits = await self._exec_in_container(
            f"grep -r -n -E '{grep_expr}' "
            "/app /src /opt /home 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc\\|test_\\|_test.py\\|mock' | "
            "head -60"
        )
        if not source_hits:
            return

        findings_map: dict[str, list[str]] = {}  # description -> list of source lines

        for line in source_hits.splitlines():
            line = line.strip()
            if not line:
                continue
            for pattern, desc, _remed in UNSAFE_LOAD_PATTERNS:
                if pattern.search(line):
                    # Special case: torch.load with weights_only=True is safe
                    if "torch.load" in desc and "weights_only=True" in line:
                        continue
                    findings_map.setdefault(desc, []).append(line)
                    break

        if not findings_map:
            return

        total_hits = sum(len(locs) for locs in findings_map.values())

        details_lines: list[str] = []
        remediations: list[str] = []
        for pattern, desc, remed in UNSAFE_LOAD_PATTERNS:
            if desc in findings_map:
                details_lines.append(f"  [{desc}]")
                for loc in findings_map[desc][:5]:
                    details_lines.append(f"    {loc[:200]}")
                remediations.append(remed)

        # torch.load without weights_only is the highest-risk pattern
        has_torch_load = any("torch.load" in d for d in findings_map)
        severity = Severity.HIGH if has_torch_load else Severity.MEDIUM

        self.add_finding(
            title=f"Unsafe model loading patterns ({total_hits} occurrences)",
            description=(
                f"Found {total_hits} instance(s) of unsafe model deserialization in "
                f"Python source code across {len(findings_map)} pattern(s). Unsafe "
                "deserialization of untrusted model files can lead to arbitrary code "
                "execution, enabling an attacker who controls the model file to "
                "compromise the entire application."
            ),
            severity=severity,
            owasp_llm=["LLM03", "LLM04"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Unsafe load patterns ({total_hits} hits)",
                    raw_data="\n".join(details_lines)[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=" ".join(remediations),
            references=[
                "https://pytorch.org/docs/stable/generated/torch.load.html",
                "https://huggingface.co/docs/safetensors/",
                "https://docs.python.org/3/library/pickle.html#restricting-globals",
            ],
            cvss_score=8.0 if severity == Severity.HIGH else 6.0,
            ai_risk_score=8.5,
        )
