"""Integration tests for DockerManager (requires Docker daemon)."""

import pytest

from aisec.docker_.manager import DockerManager

pytestmark = pytest.mark.skipif(
    True,  # Skip by default; set to False when Docker is available
    reason="Requires running Docker daemon",
)


@pytest.mark.asyncio
async def test_docker_manager_lifecycle():
    """Test full container lifecycle: setup -> inspect -> cleanup."""
    manager = DockerManager(
        target_image="alpine:latest",
        scan_id="test-integration-001",
        memory_limit="256m",
        cpu_limit=0.5,
    )

    sandbox = await manager.setup_sandbox()
    assert sandbox.target is not None

    info = manager.inspect_target()
    assert info.get("State", {}).get("Running") is True

    await manager.cleanup()
    assert manager.get_target_container() is None
