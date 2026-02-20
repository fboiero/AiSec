"""Integration test for a full scan (requires Docker daemon)."""

import pytest

pytestmark = pytest.mark.skipif(
    True,  # Skip by default
    reason="Requires running Docker daemon and target image",
)


@pytest.mark.asyncio
async def test_full_scan_alpine():
    """Run a full scan against a minimal Alpine image."""
    # This test is a placeholder for when Docker integration is ready.
    # It would:
    # 1. Create AiSecConfig with target_image="alpine:latest"
    # 2. Create ScanContext
    # 3. Set up DockerManager
    # 4. Run OrchestratorAgent
    # 5. Build report
    # 6. Verify report has expected structure
    pass
