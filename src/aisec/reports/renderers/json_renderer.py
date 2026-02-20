"""JSON report renderer.

Serialises a :class:`~aisec.core.models.ScanReport` to a pretty-printed
JSON file, handling UUID, datetime, and Enum types transparently.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from aisec.core.models import ScanReport


class _AiSecEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles AiSec domain types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        return super().default(obj)


def _to_serializable(obj: Any) -> Any:
    """Recursively convert an object tree to JSON-serializable primitives."""
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return _to_serializable(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(item) for item in obj]
    return obj


def render(report: ScanReport, output_path: Path) -> Path:
    """Render a scan report to a JSON file.

    Args:
        report: The complete scan report to serialise.
        output_path: Destination file path.  Parent directories are created
            automatically if they do not exist.

    Returns:
        The resolved path to the written JSON file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = _to_serializable(report)

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, cls=_AiSecEncoder)
        fh.write("\n")

    return output_path.resolve()
