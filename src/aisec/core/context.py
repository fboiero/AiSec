"""Scan context shared across all agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from aisec.core.events import EventBus
from aisec.core.models import AgentResult

if TYPE_CHECKING:
    from aisec.core.config import AiSecConfig


@dataclass
class ScanContext:
    """Shared state passed to all agents during a scan."""

    scan_id: UUID = field(default_factory=uuid4)
    target_image: str = ""
    target_name: str = ""
    container_id: str | None = None
    config: AiSecConfig | None = None
    agent_results: dict[str, AgentResult] = field(default_factory=dict)
    event_bus: EventBus = field(default_factory=EventBus)
    docker_manager: Any = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
