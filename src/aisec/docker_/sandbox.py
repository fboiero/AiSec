"""Sandbox network utilities for creating and managing isolated Docker environments."""

from __future__ import annotations

import logging
import time
from typing import Any

import docker
from docker.models.networks import Network

from aisec.core.exceptions import DockerError

logger = logging.getLogger(__name__)

# Containers/networks older than this (in seconds) are considered stale.
STALE_THRESHOLD_SECONDS = 3600


def _get_client() -> docker.DockerClient:
    """Obtain a Docker client, raising DockerError on failure."""
    try:
        client = docker.from_env()
        client.ping()
        return client
    except Exception as exc:
        raise DockerError(f"Cannot connect to Docker: {exc}") from exc


def create_isolated_network(
    scan_id: str,
    *,
    driver: str = "bridge",
    internal: bool = False,
    client: docker.DockerClient | None = None,
) -> Network:
    """Create a dedicated bridge network for a scan sandbox.

    Parameters
    ----------
    scan_id:
        Unique scan identifier used to derive the network name.
    driver:
        Docker network driver (default ``"bridge"``).
    internal:
        If ``True`` the network has no external connectivity, providing
        stronger isolation at the cost of the target being unable to reach
        the internet.
    client:
        Optional pre-existing Docker client.  When ``None`` a new client
        is created via ``docker.from_env()``.

    Returns
    -------
    Network
        The newly created Docker network object.
    """
    if client is None:
        client = _get_client()

    network_name = f"aisec-sandbox-{scan_id[:8]}"
    logger.info("Creating isolated network %s (driver=%s, internal=%s)", network_name, driver, internal)

    try:
        network = client.networks.create(
            name=network_name,
            driver=driver,
            internal=internal,
            labels={
                "aisec.scan_id": scan_id,
                "aisec.created_at": str(int(time.time())),
            },
        )
    except Exception as exc:
        raise DockerError(f"Failed to create network {network_name}: {exc}") from exc

    logger.info("Network %s created (id=%s)", network_name, network.short_id)
    return network


def cleanup_stale_sandboxes(
    *,
    max_age_seconds: int = STALE_THRESHOLD_SECONDS,
    client: docker.DockerClient | None = None,
) -> dict[str, Any]:
    """Find and remove old AiSec containers and networks.

    Any Docker container whose name starts with ``aisec-`` and any network
    whose name starts with ``aisec-sandbox-`` will be inspected.  If the
    resource carries an ``aisec.created_at`` label older than *max_age_seconds*
    it is stopped (containers) and removed.  Resources without the timestamp
    label are skipped to avoid accidental removal.

    Parameters
    ----------
    max_age_seconds:
        Resources older than this many seconds are considered stale.
    client:
        Optional pre-existing Docker client.

    Returns
    -------
    dict
        Summary with keys ``removed_containers`` and ``removed_networks``
        containing lists of removed resource names.
    """
    if client is None:
        client = _get_client()

    now = int(time.time())
    removed_containers: list[str] = []
    removed_networks: list[str] = []

    # --- Stale containers ---------------------------------------------------
    try:
        containers = client.containers.list(
            all=True,
            filters={"label": "aisec.scan_id"},
        )
    except Exception:
        logger.warning("Failed to list containers for cleanup")
        containers = []

    for container in containers:
        created_at_str = container.labels.get("aisec.created_at", "")
        if not created_at_str:
            # Fall back to docker container creation timestamp
            try:
                container.reload()
                created_at_str = container.attrs.get("Created", "")
            except Exception:
                continue

        try:
            created_at = int(float(created_at_str))
        except (ValueError, TypeError):
            continue

        age = now - created_at
        if age < max_age_seconds:
            continue

        name = container.name
        logger.info("Removing stale container %s (age=%ds)", name, age)
        try:
            container.stop(timeout=5)
        except Exception:
            logger.debug("Container %s already stopped or cannot be stopped", name)
        try:
            container.remove(force=True)
            removed_containers.append(name)
        except Exception:
            logger.warning("Failed to remove stale container %s", name)

    # --- Stale networks ------------------------------------------------------
    try:
        networks = client.networks.list(
            filters={"label": "aisec.scan_id"},
        )
    except Exception:
        logger.warning("Failed to list networks for cleanup")
        networks = []

    for network in networks:
        if not network.name or not network.name.startswith("aisec-sandbox-"):
            continue

        created_at_str = network.attrs.get("Labels", {}).get("aisec.created_at", "")
        if not created_at_str:
            continue

        try:
            created_at = int(float(created_at_str))
        except (ValueError, TypeError):
            continue

        age = now - created_at
        if age < max_age_seconds:
            continue

        net_name = network.name
        logger.info("Removing stale network %s (age=%ds)", net_name, age)
        try:
            network.remove()
            removed_networks.append(net_name)
        except Exception:
            logger.warning("Failed to remove stale network %s", net_name)

    summary = {
        "removed_containers": removed_containers,
        "removed_networks": removed_networks,
    }
    logger.info(
        "Stale cleanup complete: %d containers, %d networks removed",
        len(removed_containers),
        len(removed_networks),
    )
    return summary
