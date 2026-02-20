"""Filesystem monitoring for sandboxed Docker containers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aisec.core.exceptions import DockerError

if TYPE_CHECKING:
    from aisec.docker_.manager import DockerManager

logger = logging.getLogger(__name__)

# Directories to skip when scanning for secrets (to avoid noise).
_SKIP_DIRS = frozenset({
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
})

# Common patterns that indicate the presence of secrets or credentials.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?\S{16,}['\"]?")),
    ("Generic Secret", re.compile(r"(?i)(secret|password|passwd|token)\s*[=:]\s*['\"]?\S{8,}['\"]?")),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"xox[bprs]-[0-9a-zA-Z-]+")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Database URL", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://\S+:\S+@\S+")),
    ("Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.]{20,}")),
]

# File extensions that may contain secrets.
_SECRET_FILE_EXTENSIONS = (
    ".env", ".cfg", ".conf", ".config", ".ini", ".json", ".yaml", ".yml",
    ".toml", ".properties", ".xml", ".sh", ".bash", ".py", ".js", ".ts",
)


@dataclass
class FileEntry:
    """Represents a single file in a container filesystem snapshot."""

    path: str = ""
    size: int = 0
    permissions: str = ""
    owner: str = ""
    modified: str = ""


@dataclass
class FilesystemSnapshot:
    """A point-in-time snapshot of the container's filesystem."""

    files: dict[str, FileEntry] = field(default_factory=dict)
    timestamp: str = ""
    error: str | None = None


@dataclass
class FilesystemDiff:
    """Differences between two filesystem snapshots."""

    created: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)


@dataclass
class SecretFinding:
    """A potential secret or credential found in the container."""

    pattern_name: str = ""
    file_path: str = ""
    line_number: int = 0
    matched_text: str = ""


class FilesystemMonitor:
    """Monitor and analyse the filesystem inside a Docker container.

    Typical usage:

    1. ``take_snapshot()`` before the scan starts.
    2. ``take_snapshot()`` after the scan completes.
    3. ``diff_snapshots()`` to see what changed.
    4. ``scan_for_secrets()`` to search for leaked credentials.
    """

    def __init__(self) -> None:
        self._snapshots: list[FilesystemSnapshot] = []

    def take_snapshot(
        self,
        docker_manager: DockerManager,
        *,
        root: str = "/",
        max_depth: int = 5,
    ) -> FilesystemSnapshot:
        """List files in the container and return a snapshot.

        Uses ``find`` inside the container to enumerate files up to
        *max_depth* levels deep, skipping virtual filesystems like
        ``/proc`` and ``/sys``.

        Parameters
        ----------
        docker_manager:
            A :class:`DockerManager` with a running target container.
        root:
            Starting directory for the file listing.
        max_depth:
            Maximum directory depth to traverse.

        Returns
        -------
        FilesystemSnapshot
            The captured snapshot.
        """
        snapshot = FilesystemSnapshot()

        prune_clauses = " ".join(
            f"-path {d} -prune -o" for d in _SKIP_DIRS
        )
        command = (
            f"find {root} -maxdepth {max_depth} "
            f"{prune_clauses} "
            f"-type f -printf '%p\\t%s\\t%M\\t%u\\t%T+\\n'"
        )

        try:
            exit_code, output = docker_manager.exec_in_target(command)
        except DockerError as exc:
            logger.warning("Failed to take filesystem snapshot: %s", exc)
            snapshot.error = str(exc)
            self._snapshots.append(snapshot)
            return snapshot

        if exit_code != 0:
            # Fallback: simpler ls-based enumeration
            fallback_cmd = f"find {root} -maxdepth {max_depth} -type f 2>/dev/null || true"
            try:
                exit_code, output = docker_manager.exec_in_target(fallback_cmd)
            except DockerError as exc:
                snapshot.error = str(exc)
                self._snapshots.append(snapshot)
                return snapshot

            for line in output.strip().splitlines():
                path = line.strip()
                if path:
                    snapshot.files[path] = FileEntry(path=path)

            self._snapshots.append(snapshot)
            return snapshot

        for line in output.strip().splitlines():
            parts = line.split("\t", 4)
            if len(parts) < 5:
                continue
            path, size_str, perms, owner, modified = parts
            try:
                size = int(size_str)
            except ValueError:
                size = 0
            entry = FileEntry(
                path=path,
                size=size,
                permissions=perms,
                owner=owner,
                modified=modified,
            )
            snapshot.files[path] = entry

        logger.info("Filesystem snapshot: %d files captured", len(snapshot.files))
        self._snapshots.append(snapshot)
        return snapshot

    @staticmethod
    def diff_snapshots(
        before: FilesystemSnapshot,
        after: FilesystemSnapshot,
    ) -> FilesystemDiff:
        """Compare two filesystem snapshots and return the differences.

        Parameters
        ----------
        before:
            The earlier snapshot.
        after:
            The later snapshot.

        Returns
        -------
        FilesystemDiff
            Created, modified, and deleted file paths.
        """
        diff = FilesystemDiff()

        before_paths = set(before.files.keys())
        after_paths = set(after.files.keys())

        diff.created = sorted(after_paths - before_paths)
        diff.deleted = sorted(before_paths - after_paths)

        for path in before_paths & after_paths:
            b = before.files[path]
            a = after.files[path]
            # Consider modified if size or modification time changed
            if b.size != a.size or b.modified != a.modified:
                diff.modified.append(path)

        diff.modified.sort()

        logger.info(
            "Filesystem diff: %d created, %d modified, %d deleted",
            len(diff.created),
            len(diff.modified),
            len(diff.deleted),
        )
        return diff

    def scan_for_secrets(
        self,
        docker_manager: DockerManager,
        *,
        search_paths: list[str] | None = None,
        max_file_size: int = 1_048_576,  # 1 MiB
    ) -> list[SecretFinding]:
        """Search for common secret patterns in files inside the container.

        Parameters
        ----------
        docker_manager:
            A :class:`DockerManager` with a running target container.
        search_paths:
            Directories to search.  Defaults to ``["/app", "/srv", "/opt",
            "/home", "/etc"]``.
        max_file_size:
            Files larger than this (in bytes) are skipped.

        Returns
        -------
        list[SecretFinding]
            Potential secrets found.
        """
        if search_paths is None:
            search_paths = ["/app", "/srv", "/opt", "/home", "/etc"]

        findings: list[SecretFinding] = []

        # Collect candidate files
        candidate_files: list[str] = []
        for search_path in search_paths:
            extensions_pattern = " -o ".join(
                f'-name "*{ext}"' for ext in _SECRET_FILE_EXTENSIONS
            )
            command = (
                f'find {search_path} -type f \\( {extensions_pattern} \\) '
                f'-size -{max_file_size}c 2>/dev/null || true'
            )
            try:
                exit_code, output = docker_manager.exec_in_target(command)
            except DockerError:
                continue

            for line in output.strip().splitlines():
                path = line.strip()
                if path and not any(path.startswith(skip) for skip in _SKIP_DIRS):
                    candidate_files.append(path)

        logger.info("Scanning %d candidate files for secrets", len(candidate_files))

        for filepath in candidate_files[:200]:  # cap to prevent excessive scanning
            try:
                exit_code, content = docker_manager.exec_in_target(f"cat {filepath}")
            except DockerError:
                continue

            if exit_code != 0 or not content:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                for pattern_name, pattern in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        # Redact the matched text to avoid logging actual secrets
                        matched_raw = match.group(0)
                        redacted = _redact(matched_raw)
                        findings.append(
                            SecretFinding(
                                pattern_name=pattern_name,
                                file_path=filepath,
                                line_number=line_number,
                                matched_text=redacted,
                            )
                        )

        logger.info("Secret scan complete: %d potential secrets found", len(findings))
        return findings


def _redact(text: str, visible_chars: int = 6) -> str:
    """Redact a secret value, keeping only the first few characters visible."""
    if len(text) <= visible_chars:
        return "***REDACTED***"
    return text[:visible_chars] + "***REDACTED***"
