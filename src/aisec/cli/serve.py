"""``aisec serve`` command -- REST API server for programmatic access.

Provides a FastAPI-based HTTP API for running scans, retrieving results,
and monitoring scan status. Designed for CI/CD integration and enterprise
automation.

Requires: ``pip install aisec[api]`` (fastapi, uvicorn).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import typer

from aisec.cli.console import console

logger = logging.getLogger(__name__)

serve_app = typer.Typer(help="Start the AiSec REST API server.")


# ---------------------------------------------------------------------------
# In-memory scan store (SQLite upgrade in future iteration)
# ---------------------------------------------------------------------------

_scan_store: dict[str, dict[str, Any]] = {}


def _get_fastapi_app() -> Any:
    """Lazily create the FastAPI application.

    Returns:
        The configured FastAPI app instance.

    Raises:
        typer.Exit: If fastapi is not installed.
    """
    try:
        from fastapi import FastAPI, HTTPException, BackgroundTasks
        from fastapi.middleware.cors import CORSMiddleware
        from pydantic import BaseModel, Field
    except ImportError:
        console.print(
            "[red]FastAPI is required for the API server.[/red]\n"
            "Install with: [bold]pip install aisec\\[api][/bold]"
        )
        raise typer.Exit(code=1)

    import aisec

    app = FastAPI(
        title="AiSec API",
        description="REST API for deep security analysis of autonomous AI agents.",
        version=aisec.__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Pydantic models for request/response ----------------------------

    class ScanRequest(BaseModel):
        image: str = Field(..., description="Docker image to scan (e.g. 'myapp:latest')")
        agents: list[str] = Field(default=["all"], description="Agents to run")
        skip_agents: list[str] = Field(default=[], description="Agents to skip")
        formats: list[str] = Field(default=["json"], description="Output formats")
        language: str = Field(default="en", description="Report language (en/es)")

    class ScanStatus(BaseModel):
        scan_id: str
        status: str  # "pending", "running", "completed", "failed"
        image: str
        started_at: str | None = None
        completed_at: str | None = None
        finding_count: int = 0
        error: str | None = None

    class ScanResult(BaseModel):
        scan_id: str
        status: str
        image: str
        started_at: str | None = None
        completed_at: str | None = None
        report: dict[str, Any] | None = None
        error: str | None = None

    class HealthResponse(BaseModel):
        status: str = "healthy"
        version: str
        agents: int = 0
        uptime_seconds: float = 0.0

    # -- Background scan runner ------------------------------------------

    _start_time = datetime.now(timezone.utc)

    async def _run_scan_background(scan_id: str, request: ScanRequest) -> None:
        """Execute a scan in the background and store results."""
        from aisec.core.config import AiSecConfig
        from aisec.core.context import ScanContext
        from aisec.agents.orchestrator import Orchestrator
        from aisec.agents.registry import default_registry, register_core_agents
        from aisec.docker_.manager import DockerManager
        from aisec.reports.builder import ReportBuilder

        _scan_store[scan_id]["status"] = "running"
        _scan_store[scan_id]["started_at"] = datetime.now(timezone.utc).isoformat()

        try:
            config = AiSecConfig(
                agents=request.agents,
                skip_agents=request.skip_agents,
                output_formats=request.formats,
                language=request.language,
            )

            ctx = ScanContext(
                target_image=request.image,
                config=config,
            )

            register_core_agents()

            dm = DockerManager(image=request.image)
            dm.start()
            ctx.docker_manager = dm
            ctx.container_id = dm.container_id

            try:
                orch = Orchestrator(ctx, default_registry)
                await orch.run_all()
            finally:
                dm.stop()

            builder = ReportBuilder(ctx)
            report = builder.build()

            # Serialize report for JSON response
            from dataclasses import asdict
            report_dict = asdict(report)

            _scan_store[scan_id]["status"] = "completed"
            _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _scan_store[scan_id]["report"] = report_dict
            _scan_store[scan_id]["finding_count"] = report.executive_summary.total_findings

        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            _scan_store[scan_id]["status"] = "failed"
            _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _scan_store[scan_id]["error"] = str(exc)

    # -- API Endpoints ---------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["System"])
    async def health_check() -> HealthResponse:
        """Check API server health and version."""
        from aisec.agents.registry import default_registry, register_core_agents
        register_core_agents()
        uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
        return HealthResponse(
            status="healthy",
            version=aisec.__version__,
            agents=len(default_registry.get_all()),
            uptime_seconds=round(uptime, 1),
        )

    @app.post("/scan", response_model=ScanStatus, tags=["Scans"])
    async def create_scan(
        request: ScanRequest,
        background_tasks: BackgroundTasks,
    ) -> ScanStatus:
        """Submit a new security scan.

        The scan runs asynchronously. Use GET /scan/{scan_id} to poll
        for results.
        """
        scan_id = str(uuid.uuid4())
        _scan_store[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "image": request.image,
            "started_at": None,
            "completed_at": None,
            "finding_count": 0,
            "report": None,
            "error": None,
        }
        background_tasks.add_task(_run_scan_background, scan_id, request)
        return ScanStatus(
            scan_id=scan_id,
            status="pending",
            image=request.image,
        )

    @app.get("/scan/{scan_id}", response_model=ScanResult, tags=["Scans"])
    async def get_scan(scan_id: str) -> ScanResult:
        """Retrieve scan status and results."""
        if scan_id not in _scan_store:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        entry = _scan_store[scan_id]
        return ScanResult(
            scan_id=entry["scan_id"],
            status=entry["status"],
            image=entry["image"],
            started_at=entry.get("started_at"),
            completed_at=entry.get("completed_at"),
            report=entry.get("report") if entry["status"] == "completed" else None,
            error=entry.get("error"),
        )

    @app.get("/scans", tags=["Scans"])
    async def list_scans() -> list[ScanStatus]:
        """List all scans and their statuses."""
        return [
            ScanStatus(
                scan_id=e["scan_id"],
                status=e["status"],
                image=e["image"],
                started_at=e.get("started_at"),
                completed_at=e.get("completed_at"),
                finding_count=e.get("finding_count", 0),
                error=e.get("error"),
            )
            for e in _scan_store.values()
        ]

    @app.delete("/scan/{scan_id}", tags=["Scans"])
    async def delete_scan(scan_id: str) -> dict[str, str]:
        """Delete a completed or failed scan from the store."""
        if scan_id not in _scan_store:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        entry = _scan_store[scan_id]
        if entry["status"] == "running":
            raise HTTPException(status_code=409, detail="Cannot delete a running scan")
        del _scan_store[scan_id]
        return {"detail": f"Scan {scan_id} deleted"}

    return app


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@serve_app.callback(invoke_without_command=True)
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
) -> None:
    """Start the AiSec REST API server.

    Requires: pip install aisec[api]

    The API provides endpoints for:
      - POST /scan -- Submit a new security scan
      - GET  /scan/{id} -- Retrieve scan results
      - GET  /scans -- List all scans
      - GET  /health -- Health check
      - GET  /docs -- Interactive API documentation (Swagger UI)
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Uvicorn is required for the API server.[/red]\n"
            "Install with: [bold]pip install aisec\\[api][/bold]"
        )
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]AiSec API Server[/bold cyan] starting on "
        f"[bold]http://{host}:{port}[/bold]"
    )
    console.print(f"  Swagger UI: http://{host}:{port}/docs")
    console.print(f"  ReDoc:      http://{host}:{port}/redoc")
    console.print()

    uvicorn.run(
        "aisec.cli.serve:_get_fastapi_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level="info",
    )
