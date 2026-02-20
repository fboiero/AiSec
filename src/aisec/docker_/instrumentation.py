"""Instrumentation helpers for inspecting target container internals."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aisec.core.exceptions import DockerError

if TYPE_CHECKING:
    from aisec.docker_.manager import DockerManager

logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Information about a running process inside the container."""

    pid: int = 0
    user: str = ""
    cpu: str = ""
    memory: str = ""
    command: str = ""


@dataclass
class PackageInfo:
    """Information about an installed package."""

    name: str = ""
    version: str = ""
    source: str = ""  # "pip", "npm", "apt", etc.


@dataclass
class FilePermissions:
    """File permission details."""

    path: str = ""
    permissions: str = ""
    owner: str = ""
    group: str = ""
    size: int = 0
    is_world_readable: bool = False
    is_world_writable: bool = False
    is_setuid: bool = False
    is_setgid: bool = False


def get_running_processes(docker_manager: DockerManager) -> list[ProcessInfo]:
    """List all running processes inside the target container.

    Uses ``ps aux`` to enumerate processes.  Falls back to ``ps -ef`` if
    the first command is unavailable.

    Parameters
    ----------
    docker_manager:
        A :class:`DockerManager` with a running target container.

    Returns
    -------
    list[ProcessInfo]
        Process information for each running process.
    """
    processes: list[ProcessInfo] = []

    exit_code, output = _exec_or_empty(docker_manager, "ps aux --no-headers")
    if exit_code != 0 or not output.strip():
        exit_code, output = _exec_or_empty(docker_manager, "ps -ef --no-headers")

    if exit_code != 0:
        logger.warning("Unable to list processes in target container")
        return processes

    for line in output.strip().splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            # Minimal parse for shorter ps output
            if len(parts) >= 4:
                processes.append(
                    ProcessInfo(
                        user=parts[0],
                        pid=_safe_int(parts[1]),
                        command=" ".join(parts[3:]),
                    )
                )
            continue

        processes.append(
            ProcessInfo(
                user=parts[0],
                pid=_safe_int(parts[1]),
                cpu=parts[2],
                memory=parts[3],
                command=" ".join(parts[10:]),
            )
        )

    logger.info("Found %d running processes", len(processes))
    return processes


def get_environment_variables(docker_manager: DockerManager) -> dict[str, str]:
    """Retrieve environment variables from the target container.

    Reads ``/proc/1/environ`` first (the init process environment),
    falling back to ``env`` if that is not available.

    Parameters
    ----------
    docker_manager:
        A :class:`DockerManager` with a running target container.

    Returns
    -------
    dict[str, str]
        Mapping of environment variable names to values.
    """
    env_vars: dict[str, str] = {}

    # Try /proc/1/environ (NUL-separated)
    exit_code, output = _exec_or_empty(
        docker_manager, "cat /proc/1/environ"
    )
    if exit_code == 0 and output:
        for entry in output.split("\x00"):
            entry = entry.strip()
            if "=" in entry:
                key, _, value = entry.partition("=")
                env_vars[key] = value
        if env_vars:
            logger.info("Retrieved %d environment variables from /proc/1/environ", len(env_vars))
            return env_vars

    # Fallback: run env
    exit_code, output = _exec_or_empty(docker_manager, "env")
    if exit_code != 0:
        logger.warning("Unable to retrieve environment variables")
        return env_vars

    for line in output.strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            env_vars[key] = value

    logger.info("Retrieved %d environment variables", len(env_vars))
    return env_vars


def get_installed_packages(docker_manager: DockerManager) -> list[PackageInfo]:
    """Detect and list installed packages (pip and npm) in the target container.

    Attempts to run ``pip list --format=json`` and ``npm list -g --json``
    to enumerate installed packages.  Missing package managers are silently
    ignored.

    Parameters
    ----------
    docker_manager:
        A :class:`DockerManager` with a running target container.

    Returns
    -------
    list[PackageInfo]
        All detected packages across package managers.
    """
    packages: list[PackageInfo] = []

    # --- pip packages --------------------------------------------------------
    exit_code, output = _exec_or_empty(
        docker_manager, "pip list --format=columns --no-color 2>/dev/null || true"
    )
    if exit_code == 0 and output.strip():
        lines = output.strip().splitlines()
        # Skip header rows (Package/Version and dashes)
        data_lines = [l for l in lines if l and not l.startswith("-") and not l.lower().startswith("package")]
        for line in data_lines:
            parts = line.split()
            if len(parts) >= 2:
                packages.append(
                    PackageInfo(name=parts[0], version=parts[1], source="pip")
                )

    # Also try pip3 if pip yielded nothing
    if not any(p.source == "pip" for p in packages):
        exit_code, output = _exec_or_empty(
            docker_manager, "pip3 list --format=columns --no-color 2>/dev/null || true"
        )
        if exit_code == 0 and output.strip():
            lines = output.strip().splitlines()
            data_lines = [l for l in lines if l and not l.startswith("-") and not l.lower().startswith("package")]
            for line in data_lines:
                parts = line.split()
                if len(parts) >= 2:
                    packages.append(
                        PackageInfo(name=parts[0], version=parts[1], source="pip")
                    )

    # --- npm packages --------------------------------------------------------
    exit_code, output = _exec_or_empty(
        docker_manager, "npm list -g --depth=0 2>/dev/null || true"
    )
    if exit_code == 0 and output.strip():
        for line in output.strip().splitlines():
            line = line.strip()
            # npm output like: +-- package@version
            if "@" in line:
                # Remove tree characters
                cleaned = line.lstrip("+`|-\\/ ")
                if "@" in cleaned:
                    # Handle scoped packages: @scope/name@version
                    if cleaned.startswith("@"):
                        at_idx = cleaned.index("@", 1)
                    else:
                        at_idx = cleaned.index("@")
                    name = cleaned[:at_idx]
                    version = cleaned[at_idx + 1:]
                    if name:
                        packages.append(
                            PackageInfo(name=name, version=version, source="npm")
                        )

    logger.info("Found %d installed packages", len(packages))
    return packages


def get_file_permissions(
    docker_manager: DockerManager,
    path: str,
) -> FilePermissions | None:
    """Check file permissions for a path inside the target container.

    Uses ``stat`` to retrieve detailed permission information and
    derives security-relevant flags (world-readable, world-writable,
    setuid, setgid).

    Parameters
    ----------
    docker_manager:
        A :class:`DockerManager` with a running target container.
    path:
        Absolute path inside the container to inspect.

    Returns
    -------
    FilePermissions | None
        Permission details, or ``None`` if the path does not exist or
        the command fails.
    """
    exit_code, output = _exec_or_empty(
        docker_manager,
        f"stat -c '%a %U %G %s %n' {path}",
    )

    if exit_code != 0 or not output.strip():
        logger.debug("Cannot stat %s in target container", path)
        return None

    parts = output.strip().split(None, 4)
    if len(parts) < 5:
        return None

    octal_perms = parts[0]
    owner = parts[1]
    group = parts[2]
    try:
        size = int(parts[3])
    except ValueError:
        size = 0
    file_path = parts[4]

    # Also get symbolic permissions for human readability
    exit_code_ls, ls_output = _exec_or_empty(
        docker_manager,
        f"ls -la {path}",
    )
    symbolic_perms = ""
    if exit_code_ls == 0 and ls_output.strip():
        first_line = ls_output.strip().splitlines()[0]
        symbolic_perms = first_line.split()[0] if first_line.split() else ""

    # Derive security flags from octal permissions
    try:
        mode = int(octal_perms, 8)
    except ValueError:
        mode = 0

    is_world_readable = bool(mode & 0o004)
    is_world_writable = bool(mode & 0o002)
    is_setuid = bool(mode & 0o4000)
    is_setgid = bool(mode & 0o2000)

    perms = FilePermissions(
        path=file_path,
        permissions=symbolic_perms or octal_perms,
        owner=owner,
        group=group,
        size=size,
        is_world_readable=is_world_readable,
        is_world_writable=is_world_writable,
        is_setuid=is_setuid,
        is_setgid=is_setgid,
    )

    if is_setuid or is_setgid:
        logger.warning("Setuid/setgid detected on %s", path)
    if is_world_writable:
        logger.warning("World-writable file detected: %s", path)

    return perms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _exec_or_empty(docker_manager: DockerManager, command: str) -> tuple[int, str]:
    """Execute a command in the target, returning ``(1, "")`` on failure."""
    try:
        return docker_manager.exec_in_target(command)
    except DockerError:
        return 1, ""


def _safe_int(value: str) -> int:
    """Convert a string to int, returning 0 on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0
