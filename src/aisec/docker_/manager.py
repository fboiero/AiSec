"""Docker container lifecycle management."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import docker
from docker.models.containers import Container
from docker.models.networks import Network

from aisec.core.exceptions import DockerError

logger = logging.getLogger(__name__)


@dataclass
class SandboxInfo:
    """Information about a running sandbox environment."""
    network: Any = None
    target: Any = None
    sidecars: list[Any] = field(default_factory=list)
    capture_dir: str = ""


class DockerManager:
    """Manages the target container lifecycle and instrumentation sidecars."""

    def __init__(
        self,
        target_image: str,
        scan_id: str,
        memory_limit: str = "2g",
        cpu_limit: float = 1.0,
    ) -> None:
        self.target_image = target_image
        self.scan_id = scan_id
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self._client: docker.DockerClient | None = None
        self._containers: list[Container] = []
        self._network: Network | None = None
        self._sandbox: SandboxInfo | None = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            try:
                self._client = docker.from_env()
                self._client.ping()
            except Exception as exc:
                raise DockerError(f"Cannot connect to Docker: {exc}") from exc
        return self._client

    async def setup_sandbox(self) -> SandboxInfo:
        """Create isolated network, pull image, start target container."""
        logger.info("Setting up sandbox for %s", self.target_image)

        # Create isolated bridge network
        network_name = f"aisec-sandbox-{self.scan_id[:8]}"
        try:
            self._network = self.client.networks.create(
                name=network_name,
                driver="bridge",
                labels={"aisec.scan_id": self.scan_id},
            )
        except Exception as exc:
            raise DockerError(f"Failed to create network: {exc}") from exc

        # Pull target image
        logger.info("Pulling image %s", self.target_image)
        try:
            self.client.images.pull(self.target_image)
        except Exception as exc:
            raise DockerError(f"Failed to pull image {self.target_image}: {exc}") from exc

        # Run target container
        container_name = f"aisec-target-{self.scan_id[:8]}"
        try:
            target = self.client.containers.run(
                image=self.target_image,
                name=container_name,
                network=network_name,
                detach=True,
                mem_limit=self.memory_limit,
                cpu_period=100000,
                cpu_quota=int(self.cpu_limit * 100000),
                security_opt=["no-new-privileges"],
                labels={
                    "aisec.scan_id": self.scan_id,
                    "aisec.role": "target",
                },
            )
            self._containers.append(target)
        except Exception as exc:
            raise DockerError(f"Failed to start target container: {exc}") from exc

        self._sandbox = SandboxInfo(
            network=self._network,
            target=target,
            sidecars=[],
        )

        logger.info("Sandbox ready: container=%s network=%s", target.short_id, network_name)
        return self._sandbox

    def deploy_sidecar(
        self,
        image: str,
        name: str,
        *,
        pid_mode: str | None = None,
        volumes: dict[str, dict[str, str]] | None = None,
        environment: dict[str, str] | None = None,
        privileged: bool = False,
        **kwargs: Any,
    ) -> Container:
        """Deploy a sidecar container in the sandbox network.

        The sidecar shares the network with the target container and can
        optionally share the PID namespace for process monitoring (e.g. Falco).
        """
        if self._network is None:
            raise DockerError("Sandbox not initialised — call setup_sandbox() first")

        sidecar_name = f"aisec-{name}-{self.scan_id[:8]}"
        logger.info("Deploying sidecar %s (image=%s)", sidecar_name, image)

        try:
            self.client.images.pull(image)
        except Exception as exc:
            raise DockerError(f"Failed to pull sidecar image {image}: {exc}") from exc

        run_kwargs: dict[str, Any] = {
            "image": image,
            "name": sidecar_name,
            "network": self._network.name,
            "detach": True,
            "labels": {
                "aisec.scan_id": self.scan_id,
                "aisec.role": "sidecar",
            },
            "privileged": privileged,
        }
        if pid_mode:
            run_kwargs["pid_mode"] = pid_mode
        if volumes:
            run_kwargs["volumes"] = volumes
        if environment:
            run_kwargs["environment"] = environment
        run_kwargs.update(kwargs)

        try:
            container = self.client.containers.run(**run_kwargs)
            self._containers.append(container)
            if self._sandbox:
                self._sandbox.sidecars.append(container)
            logger.info("Sidecar ready: container=%s", container.short_id)
            return container
        except Exception as exc:
            raise DockerError(f"Failed to start sidecar {sidecar_name}: {exc}") from exc

    def get_target_container(self) -> Container | None:
        """Return the running target container."""
        if self._sandbox:
            return self._sandbox.target
        return None

    def inspect_target(self) -> dict[str, Any]:
        """Return docker inspect data for the target container."""
        container = self.get_target_container()
        if container is None:
            return {}
        container.reload()
        return container.attrs or {}

    def get_target_logs(self, tail: int = 100) -> str:
        """Return recent logs from the target container."""
        container = self.get_target_container()
        if container is None:
            return ""
        return container.logs(tail=tail).decode("utf-8", errors="replace")

    def exec_in_target(self, command: str) -> tuple[int, str]:
        """Execute a command inside the target container."""
        container = self.get_target_container()
        if container is None:
            raise DockerError("No target container running")
        result = container.exec_run(command, demux=False)
        output = result.output.decode("utf-8", errors="replace") if result.output else ""
        return result.exit_code, output

    def get_exposed_ports(self) -> list[dict[str, Any]]:
        """Get exposed/published ports from the target container."""
        info = self.inspect_target()
        ports = []
        config_ports = info.get("Config", {}).get("ExposedPorts", {})
        for port_proto in config_ports:
            port, proto = port_proto.split("/")
            ports.append({"port": int(port), "protocol": proto})

        network_ports = info.get("NetworkSettings", {}).get("Ports", {})
        for port_proto, bindings in (network_ports or {}).items():
            port, proto = port_proto.split("/")
            entry = {"port": int(port), "protocol": proto, "published": False}
            if bindings:
                entry["published"] = True
                entry["host_port"] = int(bindings[0].get("HostPort", 0))
            ports.append(entry)
        return ports

    def get_image_history(self) -> list[dict[str, Any]]:
        """Get Docker image layer history."""
        try:
            image = self.client.images.get(self.target_image)
            return image.history()
        except Exception:
            return []

    def export_filesystem(self) -> bytes | None:
        """Export the target container's filesystem as a tar archive."""
        container = self.get_target_container()
        if container is None:
            return None
        chunks = []
        for chunk in container.export():
            chunks.append(chunk)
        return b"".join(chunks)

    async def cleanup(self) -> None:
        """Stop and remove all containers and the sandbox network."""
        logger.info("Cleaning up sandbox for scan %s", self.scan_id[:8])
        for container in reversed(self._containers):
            try:
                container.stop(timeout=10)
                container.remove(force=True)
                logger.debug("Removed container %s", container.short_id)
            except Exception:
                logger.warning("Failed to remove container %s", container.short_id)
        self._containers.clear()

        if self._network:
            try:
                self._network.remove()
                logger.debug("Removed network")
            except Exception:
                logger.warning("Failed to remove network")
            self._network = None
        self._sandbox = None
