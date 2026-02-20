"""Parsers for Dockerfile, dependency files, and SBOMs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Dependency:
    """A parsed dependency."""

    name: str = ""
    version: str = ""
    pinned: bool = False
    source: str = ""  # "requirements.txt", "package.json", etc.


@dataclass
class DockerfileInfo:
    """Parsed Dockerfile information."""

    base_image: str = ""
    base_tag: str = ""
    exposed_ports: list[int] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    run_commands: list[str] = field(default_factory=list)
    user: str = ""
    entrypoint: str = ""
    cmd: str = ""
    copy_sources: list[str] = field(default_factory=list)


def parse_dockerfile(content: str) -> DockerfileInfo:
    """Parse a Dockerfile and extract security-relevant information."""
    info = DockerfileInfo()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        upper = line.upper()
        if upper.startswith("FROM "):
            parts = line.split()[1].split(":")
            info.base_image = parts[0]
            info.base_tag = parts[1] if len(parts) > 1 else "latest"
        elif upper.startswith("EXPOSE "):
            for port_str in line.split()[1:]:
                port_str = port_str.split("/")[0]
                if port_str.isdigit():
                    info.exposed_ports.append(int(port_str))
        elif upper.startswith("ENV "):
            match = re.match(r"ENV\s+(\S+)\s*[=\s]\s*(.*)", line, re.IGNORECASE)
            if match:
                info.env_vars[match.group(1)] = match.group(2).strip("\"'")
        elif upper.startswith("RUN "):
            info.run_commands.append(line[4:].strip())
        elif upper.startswith("USER "):
            info.user = line.split()[1]
        elif upper.startswith("ENTRYPOINT "):
            info.entrypoint = line[11:].strip()
        elif upper.startswith("CMD "):
            info.cmd = line[4:].strip()
        elif upper.startswith("COPY ") or upper.startswith("ADD "):
            parts = line.split()
            if len(parts) >= 2:
                info.copy_sources.extend(parts[1:-1])

    return info


def parse_requirements_txt(content: str) -> list[Dependency]:
    """Parse a Python requirements.txt file."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+\s*\S+)?", line)
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""
            pinned = "==" in version_spec
            version = version_spec.replace("==", "").strip() if pinned else version_spec.strip()
            deps.append(Dependency(
                name=name,
                version=version,
                pinned=pinned,
                source="requirements.txt",
            ))
    return deps


def parse_package_json(content: str) -> list[Dependency]:
    """Parse a Node.js package.json file."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            pinned = not version.startswith(("^", "~", ">", "<", "*"))
            deps.append(Dependency(
                name=name,
                version=version,
                pinned=pinned,
                source="package.json",
            ))
    return deps
