"""Tests for SyntheticContentAgent."""

import pytest

from aisec.agents.synthetic_content import (
    AI_TEXT_GEN_PATTERNS,
    AI_MEDIA_GEN_PATTERNS,
    VOICE_SYNTH_PATTERNS,
    C2PA_PATTERNS,
    WATERMARK_PATTERNS,
    CONTENT_LABEL_PATTERNS,
    DETECTION_TOOL_PATTERNS,
    POLICY_PATTERNS,
    METADATA_PATTERNS,
    SyntheticContentAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase


# ── Agent metadata ──────────────────────────────────────────────────


def test_agent_name():
    assert SyntheticContentAgent.name == "synthetic_content"


def test_agent_phase():
    assert SyntheticContentAgent.phase == AgentPhase.STATIC


def test_agent_frameworks():
    assert "LLM09" in SyntheticContentAgent.frameworks
    assert "ASI09" in SyntheticContentAgent.frameworks


def test_agent_depends_on():
    assert "output" in SyntheticContentAgent.depends_on


def test_agent_description_not_empty():
    assert len(SyntheticContentAgent.description) > 0


# ── AI text generation patterns ─────────────────────────────────────


def test_text_gen_detects_openai_chat_completion():
    assert any(p.search("openai.ChatCompletion.create") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_openai_completions():
    assert any(p.search("openai.chat.completions") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_anthropic_client():
    assert any(p.search("anthropic.Anthropic()") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_anthropic_messages():
    assert any(p.search("anthropic.messages") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_transformers_pipeline():
    assert any(p.search("transformers.pipeline('text-generation')") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_transformers_automodel():
    assert any(p.search("transformers.AutoModelForCausalLM") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_langchain_llmchain():
    assert any(p.search("langchain.LLMChain") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_langchain_chatopenai():
    assert any(p.search("langchain.ChatOpenAI") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_llama_cpp():
    assert any(p.search("llama_cpp") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_llama_index():
    assert any(p.search("llama_index") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_google_generativeai():
    assert any(p.search("google.generativeai") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_vertexai():
    assert any(p.search("vertexai") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_cohere_client():
    assert any(p.search("cohere.Client") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_cohere_generate():
    assert any(p.search("cohere.generate") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_replicate_run():
    assert any(p.search("replicate.run") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_detects_huggingface_inference():
    assert any(p.search("huggingface_hub.InferenceClient") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_case_insensitive():
    assert any(p.search("OPENAI.CHATCOMPLETION") for p in AI_TEXT_GEN_PATTERNS)


def test_text_gen_no_false_positive():
    assert not any(p.search("my_custom_library.do_stuff()") for p in AI_TEXT_GEN_PATTERNS)


# ── AI media generation patterns ────────────────────────────────────


def test_media_gen_detects_stable_diffusion_class():
    assert any(p.search("diffusers.StableDiffusion") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_diffusion_pipeline():
    assert any(p.search("diffusers.DiffusionPipeline") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_dalle():
    assert any(p.search("dall-e") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_dalle_underscore():
    assert any(p.search("dall_e") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_midjourney():
    assert any(p.search("midjourney") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_stable_diffusion_string():
    assert any(p.search("stable_diffusion") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_stable_diffusion_hyphen():
    assert any(p.search("stable-diffusion") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_stablediffusion():
    """StableDiffusion (no separator) should match."""
    assert any(p.search("StableDiffusion") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_imagen():
    assert any(p.search("imagen") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_deepfake():
    assert any(p.search("deepfake") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_faceswap():
    assert any(p.search("faceswap") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_face_swap_underscore():
    assert any(p.search("face_swap") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_first_order_motion():
    assert any(p.search("first_order_motion") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_wav2lip():
    assert any(p.search("wav2lip") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_lip_sync():
    assert any(p.search("lip_sync") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_roop():
    assert any(p.search("roop") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_insightface():
    assert any(p.search("insightface") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_deforum():
    assert any(p.search("deforum") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_detects_animatediff():
    assert any(p.search("animatediff") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_case_insensitive():
    assert any(p.search("DEEPFAKE") for p in AI_MEDIA_GEN_PATTERNS)


def test_media_gen_no_false_positive():
    assert not any(p.search("image_upload_handler") for p in AI_MEDIA_GEN_PATTERNS)


# ── Voice synthesis patterns ────────────────────────────────────────


def test_voice_synth_detects_elevenlabs():
    assert any(p.search("elevenlabs") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_tts():
    assert any(p.search("tts") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_text_to_speech():
    assert any(p.search("text_to_speech") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_text_to_speech_hyphen():
    assert any(p.search("text-to-speech") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_coqui_tts():
    assert any(p.search("coqui_tts") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_mozilla_tts():
    assert any(p.search("mozilla_tts") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_bark():
    assert any(p.search("bark") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_tortoise_tts():
    assert any(p.search("tortoise_tts") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_voice_cloning():
    assert any(p.search("voice_cloning") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_real_time_voice():
    assert any(p.search("real_time_voice") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_speech_synthesis():
    assert any(p.search("speech_synthesis") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_pyttsx3():
    assert any(p.search("pyttsx3") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_gtts():
    assert any(p.search("gTTS") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_amazon_polly():
    assert any(p.search("amazon.polly") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_azure_speech():
    assert any(p.search("azure.cognitiveservices.speech") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_detects_resemble_ai():
    assert any(p.search("resemble_ai") for p in VOICE_SYNTH_PATTERNS)


def test_voice_synth_case_insensitive():
    assert any(p.search("ELEVENLABS") for p in VOICE_SYNTH_PATTERNS)


# ── C2PA patterns ──────────────────────────────────────────────────


def test_c2pa_detects_c2pa_keyword():
    assert any(p.search("c2pa") for p in C2PA_PATTERNS)


def test_c2pa_detects_content_authenticity():
    assert any(p.search("content_authenticity") for p in C2PA_PATTERNS)


def test_c2pa_detects_content_credentials():
    assert any(p.search("content_credentials") for p in C2PA_PATTERNS)


def test_c2pa_detects_content_provenance():
    assert any(p.search("content_provenance") for p in C2PA_PATTERNS)


def test_c2pa_detects_coalition_content_provenance():
    assert any(p.search("coalition for content provenance") for p in C2PA_PATTERNS)


def test_c2pa_detects_manifest_store():
    assert any(p.search("manifest_store") for p in C2PA_PATTERNS)


def test_c2pa_detects_c2pa_python():
    assert any(p.search("c2pa-python") for p in C2PA_PATTERNS)


def test_c2pa_detects_c2pa_rs():
    assert any(p.search("c2pa-rs") for p in C2PA_PATTERNS)


def test_c2pa_case_insensitive():
    assert any(p.search("C2PA") for p in C2PA_PATTERNS)


def test_c2pa_no_false_positive():
    assert not any(p.search("totally unrelated text") for p in C2PA_PATTERNS)


# ── Watermark patterns ─────────────────────────────────────────────


def test_watermark_detects_watermark():
    assert any(p.search("watermark") for p in WATERMARK_PATTERNS)


def test_watermark_detects_steganography():
    assert any(p.search("steganography") for p in WATERMARK_PATTERNS)


def test_watermark_detects_invisible_watermark():
    assert any(p.search("invisible_watermark") for p in WATERMARK_PATTERNS)


def test_watermark_detects_digital_watermark():
    assert any(p.search("digital_watermark") for p in WATERMARK_PATTERNS)


def test_watermark_detects_robust_watermark():
    assert any(p.search("robust_watermark") for p in WATERMARK_PATTERNS)


def test_watermark_detects_perceptual_hash():
    assert any(p.search("perceptual_hash") for p in WATERMARK_PATTERNS)


def test_watermark_detects_content_fingerprint():
    assert any(p.search("content_fingerprint") for p in WATERMARK_PATTERNS)


def test_watermark_detects_ai_watermark():
    assert any(p.search("ai_watermark") for p in WATERMARK_PATTERNS)


def test_watermark_case_insensitive():
    assert any(p.search("WATERMARK") for p in WATERMARK_PATTERNS)


def test_watermark_no_false_positive():
    assert not any(p.search("clean_image_processor") for p in WATERMARK_PATTERNS)


# ── Content label patterns ─────────────────────────────────────────


def test_label_detects_ai_generated():
    assert any(p.search("ai_generated") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_ai_generated_hyphen():
    assert any(p.search("ai-generated") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_generated_by_ai():
    assert any(p.search("generated_by_ai") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_synthetic_content():
    assert any(p.search("synthetic_content") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_machine_generated():
    assert any(p.search("machine_generated") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_artificially_generated():
    assert any(p.search("artificially_generated") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_content_disclaimer():
    assert any(p.search("content_disclaimer") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_ai_disclosure():
    assert any(p.search("ai_disclosure") for p in CONTENT_LABEL_PATTERNS)


def test_label_detects_automated_content():
    assert any(p.search("automated_content") for p in CONTENT_LABEL_PATTERNS)


def test_label_case_insensitive():
    assert any(p.search("AI_GENERATED") for p in CONTENT_LABEL_PATTERNS)


# ── Detection tool patterns ────────────────────────────────────────


def test_detection_detects_deepfake_detect():
    assert any(p.search("deepfake_detect") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_fake_detect():
    assert any(p.search("fake_detect") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_ai_detect():
    assert any(p.search("ai_detect") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_gptzero():
    assert any(p.search("gptzero") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_originality_ai():
    assert any(p.search("originality_ai") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_turnitin():
    assert any(p.search("turnitin") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_content_moderation():
    assert any(p.search("content_moderation") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_nsfw_detect():
    assert any(p.search("nsfw_detect") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_safety_classifier():
    assert any(p.search("safety_classifier") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_toxicity_detect():
    assert any(p.search("toxicity_detect") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_fact_check():
    assert any(p.search("fact_check") for p in DETECTION_TOOL_PATTERNS)


def test_detection_detects_claim_verification():
    assert any(p.search("claim_verification") for p in DETECTION_TOOL_PATTERNS)


def test_detection_case_insensitive():
    assert any(p.search("GPTZERO") for p in DETECTION_TOOL_PATTERNS)


def test_detection_no_false_positive():
    assert not any(p.search("my_utility_function()") for p in DETECTION_TOOL_PATTERNS)


# ── Policy patterns ────────────────────────────────────────────────


def test_policy_detects_content_policy():
    assert any(p.search("content_policy") for p in POLICY_PATTERNS)


def test_policy_detects_acceptable_use():
    assert any(p.search("acceptable_use") for p in POLICY_PATTERNS)


def test_policy_detects_usage_policy():
    assert any(p.search("usage_policy") for p in POLICY_PATTERNS)


def test_policy_detects_terms_of_service():
    assert any(p.search("terms_of_service") for p in POLICY_PATTERNS)


def test_policy_detects_terms_of_use():
    assert any(p.search("terms_of_use") for p in POLICY_PATTERNS)


def test_policy_detects_content_guideline():
    assert any(p.search("content_guideline") for p in POLICY_PATTERNS)


def test_policy_detects_output_policy():
    assert any(p.search("output_policy") for p in POLICY_PATTERNS)


def test_policy_detects_responsible_ai_policy():
    assert any(p.search("responsible_ai_policy") for p in POLICY_PATTERNS)


def test_policy_case_insensitive():
    assert any(p.search("CONTENT_POLICY") for p in POLICY_PATTERNS)


def test_policy_no_false_positive():
    assert not any(p.search("database_config_setting") for p in POLICY_PATTERNS)


# ── Metadata patterns ──────────────────────────────────────────────


def test_metadata_detects_exif():
    assert any(p.search("exif") for p in METADATA_PATTERNS)


def test_metadata_detects_metadata_strip():
    assert any(p.search("metadata_strip") for p in METADATA_PATTERNS)


def test_metadata_detects_metadata_preserve():
    assert any(p.search("metadata_preserve") for p in METADATA_PATTERNS)


def test_metadata_detects_iptc():
    assert any(p.search("iptc") for p in METADATA_PATTERNS)


def test_metadata_detects_xmp():
    assert any(p.search("xmp") for p in METADATA_PATTERNS)


def test_metadata_detects_piexif():
    assert any(p.search("piexif") for p in METADATA_PATTERNS)


def test_metadata_detects_pillow_exif():
    assert any(p.search("pillow.exif") for p in METADATA_PATTERNS)


def test_metadata_detects_exifread():
    assert any(p.search("exifread") for p in METADATA_PATTERNS)


def test_metadata_case_insensitive():
    assert any(p.search("EXIF") for p in METADATA_PATTERNS)


def test_metadata_no_false_positive():
    assert not any(p.search("plain_config_loader") for p in METADATA_PATTERNS)


# ── Pattern group completeness ──────────────────────────────────────


def test_all_pattern_groups_are_non_empty():
    groups = [
        AI_TEXT_GEN_PATTERNS,
        AI_MEDIA_GEN_PATTERNS,
        VOICE_SYNTH_PATTERNS,
        C2PA_PATTERNS,
        WATERMARK_PATTERNS,
        CONTENT_LABEL_PATTERNS,
        DETECTION_TOOL_PATTERNS,
        POLICY_PATTERNS,
        METADATA_PATTERNS,
    ]
    for group in groups:
        assert len(group) > 0


def test_all_patterns_are_compiled_regex():
    """All items in every pattern group must be compiled regex objects."""
    import re

    groups = [
        AI_TEXT_GEN_PATTERNS,
        AI_MEDIA_GEN_PATTERNS,
        VOICE_SYNTH_PATTERNS,
        C2PA_PATTERNS,
        WATERMARK_PATTERNS,
        CONTENT_LABEL_PATTERNS,
        DETECTION_TOOL_PATTERNS,
        POLICY_PATTERNS,
        METADATA_PATTERNS,
    ]
    for group in groups:
        for pat in group:
            assert isinstance(pat, re.Pattern), f"{pat!r} is not a compiled regex"


# ── Helper methods ──────────────────────────────────────────────────


def test_search_returns_hits():
    """_search should return (path, snippet) tuples for matches."""
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    files = {"/app/main.py": "import openai.ChatCompletion\nresult = call()"}
    hits = agent._search(files, AI_TEXT_GEN_PATTERNS)
    assert len(hits) > 0
    assert hits[0][0] == "/app/main.py"


def test_search_returns_empty_for_no_match():
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    files = {"/app/main.py": "import os\nprint('hello')"}
    hits = agent._search(files, AI_TEXT_GEN_PATTERNS)
    assert hits == []


def test_has_returns_true_on_match():
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    files = {"/app/main.py": "use elevenlabs voice API"}
    assert agent._has(files, VOICE_SYNTH_PATTERNS) is True


def test_has_returns_false_on_no_match():
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    files = {"/app/main.py": "import os\nprint('hello')"}
    assert agent._has(files, VOICE_SYNTH_PATTERNS) is False


def test_has_env_detects_keyword():
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    env_vars = ["CONTENT_POLICY=strict", "APP_PORT=8080"]
    assert agent._has_env(env_vars, ["content_policy"]) is True


def test_has_env_returns_false_when_missing():
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    env_vars = ["APP_PORT=8080", "DEBUG=true"]
    assert agent._has_env(env_vars, ["content_policy"]) is False


# ── Agent instantiation ───────────────────────────────────────────


def test_agent_creates_no_findings_without_container():
    """Agent should produce no findings when no container_id is set."""
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    assert agent.findings == []


@pytest.mark.asyncio
async def test_agent_run_returns_result():
    """Agent.run() should return an AgentResult even without Docker."""
    ctx = ScanContext(target_image="test:latest")
    agent = SyntheticContentAgent(ctx)
    result = await agent.run()
    assert result.agent == "synthetic_content"
    assert result.error is None
