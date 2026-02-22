"""Synthetic content and deepfake detection agent.

Analyses AI agent containers for synthetic content risks including:
AI-generated text detection capabilities, voice clone protections,
image/video manipulation safeguards, C2PA content provenance verification,
watermark detection mechanisms, and synthetic content policy enforcement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled pattern groups
# ---------------------------------------------------------------------------
_P = re.compile

# AI text generation frameworks and libraries
AI_TEXT_GEN_PATTERNS = [
    _P(r"(?i)openai\.(ChatCompletion|Completion|chat\.completions)"),
    _P(r"(?i)anthropic\.(Anthropic|Client|messages)"),
    _P(r"(?i)transformers\.(pipeline|AutoModelForCausalLM|GPT)"),
    _P(r"(?i)langchain\.(LLMChain|ChatOpenAI|ChatAnthropic)"),
    _P(r"(?i)llama[_\-]?cpp|llama_index"),
    _P(r"(?i)google\.generativeai|vertexai"),
    _P(r"(?i)cohere\.(Client|generate)"),
    _P(r"(?i)replicate\.(run|Client)"),
    _P(r"(?i)huggingface_hub\.InferenceClient"),
]

# AI image/video generation
AI_MEDIA_GEN_PATTERNS = [
    _P(r"(?i)diffusers\.(StableDiffusion|DiffusionPipeline)"),
    _P(r"(?i)dall[_\-]?e|dalle"),
    _P(r"(?i)midjourney"),
    _P(r"(?i)stable[_\-]?diffusion"),
    _P(r"(?i)imagen"),
    _P(r"(?i)deepfake|face[_\-]?swap|faceswap"),
    _P(r"(?i)first[_\-]?order[_\-]?motion"),
    _P(r"(?i)wav2lip|lip[_\-]?sync"),
    _P(r"(?i)roop|insightface"),
    _P(r"(?i)deforum|animatediff"),
]

# Voice synthesis / cloning
VOICE_SYNTH_PATTERNS = [
    _P(r"(?i)elevenlabs"),
    _P(r"(?i)tts|text[_\-]?to[_\-]?speech"),
    _P(r"(?i)coqui[_\-]?tts|mozilla[_\-]?tts"),
    _P(r"(?i)bark|tortoise[_\-]?tts"),
    _P(r"(?i)voice[_\-]?clon"),
    _P(r"(?i)real[_\-]?time[_\-]?voice"),
    _P(r"(?i)speech[_\-]?synthesis"),
    _P(r"(?i)pyttsx3|gTTS|amazon\.polly"),
    _P(r"(?i)azure\.cognitiveservices\.speech"),
    _P(r"(?i)resemble[_\-]?ai"),
]

# C2PA / Content Provenance patterns
C2PA_PATTERNS = [
    _P(r"(?i)\bc2pa\b"),
    _P(r"(?i)content[_\-\s]?authenticity"),
    _P(r"(?i)content[_\-\s]?credentials"),
    _P(r"(?i)content[_\-\s]?provenance"),
    _P(r"(?i)coalition.*content.*provenance"),
    _P(r"(?i)manifest[_\-\s]?store"),
    _P(r"(?i)c2pa[_\-]?rs|c2pa[_\-]?python"),
]

# Watermarking patterns
WATERMARK_PATTERNS = [
    _P(r"(?i)\bwatermark"),
    _P(r"(?i)steganograph"),
    _P(r"(?i)invisible[_\-\s]?watermark"),
    _P(r"(?i)digital[_\-\s]?watermark"),
    _P(r"(?i)robust[_\-\s]?watermark"),
    _P(r"(?i)perceptual[_\-\s]?hash"),
    _P(r"(?i)content[_\-\s]?fingerprint"),
    _P(r"(?i)ai[_\-\s]?watermark"),
]

# AI content labeling / disclosure patterns
CONTENT_LABEL_PATTERNS = [
    _P(r"(?i)ai[_\-\s]?generated"),
    _P(r"(?i)generated[_\-\s]?by[_\-\s]?ai"),
    _P(r"(?i)synthetic[_\-\s]?content"),
    _P(r"(?i)machine[_\-\s]?generated"),
    _P(r"(?i)artificially[_\-\s]?generated"),
    _P(r"(?i)content[_\-\s]?disclaimer"),
    _P(r"(?i)ai[_\-\s]?disclosure"),
    _P(r"(?i)automated[_\-\s]?content"),
]

# Deepfake detection tools
DETECTION_TOOL_PATTERNS = [
    _P(r"(?i)deepfake[_\-\s]?detect"),
    _P(r"(?i)fake[_\-\s]?detect"),
    _P(r"(?i)ai[_\-\s]?detect"),
    _P(r"(?i)gptzero|originality[_\-\s]?ai|turnitin"),
    _P(r"(?i)content[_\-\s]?moderat"),
    _P(r"(?i)nsfw[_\-\s]?detect|safety[_\-\s]?classifier"),
    _P(r"(?i)toxicity[_\-\s]?detect"),
    _P(r"(?i)fact[_\-\s]?check|claim[_\-\s]?verif"),
]

# Content policy enforcement
POLICY_PATTERNS = [
    _P(r"(?i)content[_\-\s]?policy"),
    _P(r"(?i)acceptable[_\-\s]?use"),
    _P(r"(?i)usage[_\-\s]?policy"),
    _P(r"(?i)terms[_\-\s]?of[_\-\s]?(?:service|use)"),
    _P(r"(?i)content[_\-\s]?guideline"),
    _P(r"(?i)output[_\-\s]?policy"),
    _P(r"(?i)responsible[_\-\s]?ai[_\-\s]?policy"),
]

# Metadata stripping / preservation
METADATA_PATTERNS = [
    _P(r"(?i)exif"),
    _P(r"(?i)metadata[_\-\s]?strip"),
    _P(r"(?i)metadata[_\-\s]?preserv"),
    _P(r"(?i)iptc"),
    _P(r"(?i)xmp"),
    _P(r"(?i)piexif|pillow.*exif|exifread"),
]

_SCAN_DIRS = "/app /src /opt /home /etc"
_ALL_EXTENSIONS = (
    "*.py *.js *.ts *.go *.java *.rs *.rb "
    "*.yaml *.yml *.toml *.ini *.cfg *.conf *.json *.env *.md *.txt"
)


class SyntheticContentAgent(BaseAgent):
    """Detect and assess synthetic content and deepfake risks."""

    name: ClassVar[str] = "synthetic_content"
    description: ClassVar[str] = (
        "Detects AI-generated text, voice cloning, image/video manipulation, "
        "verifies content provenance (C2PA), watermark presence, and "
        "synthetic content policy enforcement."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM09", "ASI09"]
    depends_on: ClassVar[list[str]] = ["output"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all synthetic content detection checks."""
        file_contents = await self._collect_file_contents()
        container_info = await self._get_container_info()
        env_vars = container_info.get("Config", {}).get("Env") or []

        await self._check_text_generation(file_contents, env_vars)
        await self._check_media_generation(file_contents, env_vars)
        await self._check_voice_synthesis(file_contents, env_vars)
        await self._check_content_provenance(file_contents)
        await self._check_watermarking(file_contents)
        await self._check_content_labeling(file_contents)
        await self._check_detection_tools(file_contents)
        await self._check_metadata_handling(file_contents)
        await self._check_content_policy(file_contents, env_vars)

    # ------------------------------------------------------------------
    # Container / Docker helpers
    # ------------------------------------------------------------------

    def _exec(self, cmd: str) -> tuple[int, str]:
        dm = self.context.docker_manager
        if dm is not None:
            return dm.exec_in_target(cmd)
        return 1, ""

    async def _get_container_info(self) -> dict[str, Any]:
        dm = self.context.docker_manager
        if dm is not None:
            try:
                return await asyncio.to_thread(dm.inspect_target)
            except Exception:
                pass
        cid = self.context.container_id
        if not cid:
            return {}
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            data = json.loads(stdout)
            return data[0] if isinstance(data, list) else data
        except Exception:
            return {}

    async def _collect_file_contents(self) -> dict[str, str]:
        if not self.context.container_id and self.context.docker_manager is None:
            return {}
        ext_args = " -o ".join(f"-name '{e}'" for e in _ALL_EXTENSIONS.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            f"-size -1024k 2>/dev/null | head -200"
        )
        try:
            rc, out = await asyncio.to_thread(self._exec, f"sh -c {find_cmd!r}")
            if rc != 0:
                return {}
            file_list = out.strip().splitlines()
        except Exception:
            return {}
        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                rc, data = await asyncio.to_thread(self._exec, f"head -c 65536 {fpath}")
                if rc == 0 and data:
                    contents[fpath] = data
            except Exception:
                continue
        return contents

    # ------------------------------------------------------------------
    # Pattern search helpers
    # ------------------------------------------------------------------

    def _search(self, files: dict[str, str], patterns: list[re.Pattern[str]]) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for fpath, content in files.items():
            for pat in patterns:
                for m in list(pat.finditer(content))[:3]:
                    s, e = max(0, m.start() - 40), min(len(content), m.end() + 60)
                    hits.append((fpath, content[s:e].strip().replace("\n", " ")))
        return hits

    def _has(self, files: dict[str, str], patterns: list[re.Pattern[str]]) -> bool:
        for content in files.values():
            for pat in patterns:
                if pat.search(content):
                    return True
        return False

    def _has_env(self, env_vars: list[str], keywords: list[str]) -> bool:
        for ev in env_vars:
            ev_lower = str(ev).lower()
            if any(kw in ev_lower for kw in keywords):
                return True
        return False

    # ------------------------------------------------------------------
    # 1. AI Text Generation Assessment
    # ------------------------------------------------------------------

    async def _check_text_generation(
        self, files: dict[str, str], env_vars: list[str],
    ) -> None:
        cid = self.context.container_id
        gen_hits = self._search(files, AI_TEXT_GEN_PATTERNS)
        if not gen_hits:
            return

        gen_files = sorted({f for f, _ in gen_hits})

        # Check if there are disclosure mechanisms
        has_disclosure = self._has(files, CONTENT_LABEL_PATTERNS)

        if not has_disclosure:
            self.add_finding(
                title=f"AI text generation without disclosure ({len(gen_files)} files)",
                description=(
                    f"Found AI text generation capabilities in {len(gen_files)} file(s) "
                    "but no AI content disclosure or labeling mechanism. EU AI Act Art. 50 "
                    "requires disclosure when users interact with AI-generated content."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MAP"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Text generation without disclosure",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in gen_hits[:15]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Add AI content disclosure: label generated text as AI-produced, "
                    "embed machine-readable metadata (C2PA), and inform users when they "
                    "interact with AI-generated content per EU AI Act Art. 50."
                ),
                cvss_score=4.0, ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 2. AI Media Generation (Image/Video)
    # ------------------------------------------------------------------

    async def _check_media_generation(
        self, files: dict[str, str], env_vars: list[str],
    ) -> None:
        cid = self.context.container_id
        media_hits = self._search(files, AI_MEDIA_GEN_PATTERNS)
        if not media_hits:
            return

        media_files = sorted({f for f, _ in media_hits})
        has_watermark = self._has(files, WATERMARK_PATTERNS)
        has_c2pa = self._has(files, C2PA_PATTERNS)
        has_detection = self._has(files, DETECTION_TOOL_PATTERNS)

        # Deepfake-specific patterns
        deepfake_hits = [
            (f, s) for f, s in media_hits
            if any(kw in s.lower() for kw in ("deepfake", "face_swap", "faceswap", "roop", "wav2lip"))
        ]

        if deepfake_hits:
            self.add_finding(
                title=f"Deepfake generation capabilities detected ({len(deepfake_hits)} refs)",
                description=(
                    "Face-swapping or deepfake generation tools detected. These pose "
                    "significant risks for identity fraud, disinformation, and non-consensual "
                    "synthetic media. EU AI Act Art. 50(3) requires deepfake disclosure."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MAP", "MANAGE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Deepfake capabilities",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in deepfake_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Implement mandatory disclosure for deepfake content per EU AI Act "
                    "Art. 50(3). Add watermarking, C2PA provenance metadata, and consent "
                    "verification before generating synthetic media of real people."
                ),
                cvss_score=7.0, ai_risk_score=8.5,
            )

        if not has_watermark and not has_c2pa:
            self.add_finding(
                title=f"AI media generation without provenance tracking ({len(media_files)} files)",
                description=(
                    f"AI image/video generation found in {len(media_files)} file(s) but no "
                    "watermarking or C2PA content provenance. Generated media can be "
                    "distributed without attribution, enabling misuse and disinformation."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Media generation without provenance",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in media_hits[:15]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Embed C2PA content credentials in all AI-generated media. Add invisible "
                    "watermarks using robust watermarking algorithms. Implement content "
                    "provenance tracking per EU AI Act Art. 50(4)."
                ),
                cvss_score=5.0, ai_risk_score=7.0,
            )

    # ------------------------------------------------------------------
    # 3. Voice Synthesis / Cloning
    # ------------------------------------------------------------------

    async def _check_voice_synthesis(
        self, files: dict[str, str], env_vars: list[str],
    ) -> None:
        cid = self.context.container_id
        voice_hits = self._search(files, VOICE_SYNTH_PATTERNS)
        if not voice_hits:
            return

        voice_files = sorted({f for f, _ in voice_hits})

        # Check for voice cloning specifically
        clone_hits = [
            (f, s) for f, s in voice_hits
            if any(kw in s.lower() for kw in ("voice_clon", "voice-clon", "clone", "elevenlabs", "resemble"))
        ]

        has_disclosure = self._has(files, CONTENT_LABEL_PATTERNS)

        if clone_hits:
            self.add_finding(
                title=f"Voice cloning capabilities detected ({len(clone_hits)} refs)",
                description=(
                    "Voice cloning or real-time voice synthesis detected. This enables "
                    "impersonation attacks, voice-based fraud (vishing), and unauthorized "
                    "replication of individuals' voices."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MAP", "MANAGE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Voice cloning capabilities",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in clone_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Implement voice consent verification before cloning. Add audio "
                    "watermarks to synthetic speech. Disclose synthetic voice to listeners. "
                    "Rate-limit voice generation and log all synthesis requests."
                ),
                cvss_score=6.5, ai_risk_score=8.0,
            )
        elif not has_disclosure:
            self.add_finding(
                title=f"Voice synthesis without disclosure ({len(voice_files)} files)",
                description=(
                    f"Text-to-speech or voice synthesis in {len(voice_files)} file(s) without "
                    "disclosure mechanisms. Users may not realize they are hearing AI-generated speech."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Voice synthesis without disclosure",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in voice_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Disclose to users when they hear AI-generated speech. Add audio "
                    "watermarks for provenance tracking."
                ),
                cvss_score=3.0, ai_risk_score=5.0,
            )

    # ------------------------------------------------------------------
    # 4. Content Provenance (C2PA)
    # ------------------------------------------------------------------

    async def _check_content_provenance(self, files: dict[str, str]) -> None:
        cid = self.context.container_id
        has_media_gen = self._has(files, AI_MEDIA_GEN_PATTERNS)
        has_text_gen = self._has(files, AI_TEXT_GEN_PATTERNS)

        if not has_media_gen and not has_text_gen:
            return

        has_c2pa = self._has(files, C2PA_PATTERNS)
        if has_c2pa:
            c2pa_hits = self._search(files, C2PA_PATTERNS)
            self.add_finding(
                title="C2PA content provenance integration detected",
                description=(
                    "Content Authenticity Initiative (C2PA) integration found. This enables "
                    "cryptographic content provenance tracking for AI-generated media."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM09"], nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="C2PA integration",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in c2pa_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation="Ensure C2PA credentials are applied to all generated content.",
            )
        elif has_media_gen:
            self.add_finding(
                title="Missing C2PA content provenance for AI-generated media",
                description=(
                    "AI media generation detected without C2PA (Coalition for Content "
                    "Provenance and Authenticity) integration. Content provenance enables "
                    "verifiable attribution and tamper detection for AI-generated content."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="No C2PA provenance",
                    raw_data=f"Media generation detected but no C2PA patterns in {len(files)} files",
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Integrate C2PA (c2pa-python or c2pa-rs) to embed cryptographic "
                    "content credentials in all AI-generated images, videos, and audio. "
                    "This satisfies EU AI Act Art. 50(4) machine-readable content labeling."
                ),
                cvss_score=4.5, ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 5. Watermarking
    # ------------------------------------------------------------------

    async def _check_watermarking(self, files: dict[str, str]) -> None:
        cid = self.context.container_id
        has_gen = self._has(files, AI_MEDIA_GEN_PATTERNS) or self._has(files, AI_TEXT_GEN_PATTERNS)
        if not has_gen:
            return

        wm_hits = self._search(files, WATERMARK_PATTERNS)
        if wm_hits:
            self.add_finding(
                title=f"Watermarking mechanism detected ({len(wm_hits)} refs)",
                description="Watermarking implementation found for AI-generated content tracking.",
                severity=Severity.INFO,
                owasp_llm=["LLM09"], nist_ai_rmf=["MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Watermarking detected",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in wm_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation="Ensure watermarks are robust against common transformations.",
            )
        else:
            self.add_finding(
                title="No watermarking for AI-generated content",
                description=(
                    "AI content generation detected but no watermarking mechanism. "
                    "Without watermarks, generated content cannot be traced back to its "
                    "source, enabling misattribution and misuse."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="No watermarking",
                    raw_data=f"Content generation in {len(files)} files, no watermark patterns",
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Implement invisible watermarking for AI-generated content: "
                    "use robust image watermarking (e.g., DwtDct, RivaGAN), "
                    "text watermarking (e.g., Unicode zero-width, statistical), "
                    "and audio watermarking algorithms."
                ),
                cvss_score=4.0, ai_risk_score=6.0,
            )

    # ------------------------------------------------------------------
    # 6. Content Labeling & Disclosure
    # ------------------------------------------------------------------

    async def _check_content_labeling(self, files: dict[str, str]) -> None:
        cid = self.context.container_id
        has_gen = self._has(files, AI_TEXT_GEN_PATTERNS) or self._has(files, AI_MEDIA_GEN_PATTERNS)
        if not has_gen:
            return

        label_hits = self._search(files, CONTENT_LABEL_PATTERNS)
        if label_hits:
            self.add_finding(
                title=f"AI content labeling detected ({len(label_hits)} refs)",
                description="AI-generated content labeling and disclosure mechanisms found.",
                severity=Severity.INFO,
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Content labeling",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in label_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation="Verify labels are applied consistently to all generated outputs.",
            )

    # ------------------------------------------------------------------
    # 7. Detection Tools Assessment
    # ------------------------------------------------------------------

    async def _check_detection_tools(self, files: dict[str, str]) -> None:
        cid = self.context.container_id
        has_gen = (
            self._has(files, AI_TEXT_GEN_PATTERNS)
            or self._has(files, AI_MEDIA_GEN_PATTERNS)
            or self._has(files, VOICE_SYNTH_PATTERNS)
        )
        if not has_gen:
            return

        det_hits = self._search(files, DETECTION_TOOL_PATTERNS)
        if det_hits:
            self.add_finding(
                title=f"Synthetic content detection tools present ({len(det_hits)} refs)",
                description=(
                    "Detection mechanisms for synthetic or AI-generated content found, "
                    "including content moderation, fact checking, or deepfake detection."
                ),
                severity=Severity.INFO,
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Detection tools present",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in det_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation="Ensure detection tools are regularly updated with latest models.",
            )
        else:
            self.add_finding(
                title="No synthetic content detection or moderation tools",
                description=(
                    "AI content generation detected but no content moderation, "
                    "fact-checking, or deepfake detection tools found. Without detection "
                    "mechanisms, harmful synthetic content cannot be identified before distribution."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="No detection tools",
                    raw_data=f"Generation in {len(files)} files, no detection patterns",
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Add content moderation (OpenAI Moderation API, Perspective API, "
                    "or custom classifiers). Implement fact-checking pipelines and "
                    "deepfake detection for media content before distribution."
                ),
                cvss_score=5.0, ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 8. Metadata Handling
    # ------------------------------------------------------------------

    async def _check_metadata_handling(self, files: dict[str, str]) -> None:
        cid = self.context.container_id
        has_media = self._has(files, AI_MEDIA_GEN_PATTERNS)
        if not has_media:
            return

        meta_hits = self._search(files, METADATA_PATTERNS)
        strip_re = re.compile(r"(?i)(?:strip|remov|delet|clear)[_\-\s]?(?:exif|metadata|iptc|xmp)")
        strip_hits = [
            (f, s) for f, s in meta_hits
            if strip_re.search(s)
        ]

        if strip_hits:
            self.add_finding(
                title=f"Metadata stripping detected on AI-generated media ({len(strip_hits)} refs)",
                description=(
                    "EXIF/IPTC/XMP metadata stripping found alongside media generation. "
                    "Removing metadata from AI-generated content destroys provenance "
                    "information needed for content authenticity verification."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary="Metadata stripping",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in strip_hits[:10]),
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Preserve provenance metadata in AI-generated media. If privacy "
                    "requires metadata removal, retain C2PA content credentials and "
                    "watermarks as alternative provenance mechanisms."
                ),
                cvss_score=4.0, ai_risk_score=5.5,
            )

    # ------------------------------------------------------------------
    # 9. Content Policy Enforcement
    # ------------------------------------------------------------------

    async def _check_content_policy(
        self, files: dict[str, str], env_vars: list[str],
    ) -> None:
        cid = self.context.container_id
        has_gen = (
            self._has(files, AI_TEXT_GEN_PATTERNS)
            or self._has(files, AI_MEDIA_GEN_PATTERNS)
            or self._has(files, VOICE_SYNTH_PATTERNS)
        )
        if not has_gen:
            return

        has_policy = (
            self._has(files, POLICY_PATTERNS)
            or self._has_env(env_vars, ["content_policy", "usage_policy", "responsible_ai"])
        )

        if not has_policy:
            self.add_finding(
                title="No synthetic content policy enforcement",
                description=(
                    "AI content generation capabilities detected but no content policy "
                    "or acceptable use enforcement found. Without policy enforcement, "
                    "the agent may generate harmful, misleading, or prohibited content."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"], owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[Evidence(
                    type="config",
                    summary="No content policy",
                    raw_data=f"Generation in {len(files)} files, no policy patterns or env vars",
                    location=f"container:{cid}",
                )],
                remediation=(
                    "Define and enforce a synthetic content policy covering: prohibited "
                    "content types, required disclosures, watermarking requirements, "
                    "consent for likeness/voice cloning, and content moderation thresholds. "
                    "Implement as code-level guardrails, not just documentation."
                ),
                cvss_score=4.5, ai_risk_score=6.5,
            )
