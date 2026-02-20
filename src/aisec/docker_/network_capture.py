"""Network capture and analysis for sandboxed containers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aisec.core.exceptions import DockerError

if TYPE_CHECKING:
    from aisec.docker_.manager import DockerManager

logger = logging.getLogger(__name__)

# Optional dependency -- gracefully degrade when scapy is unavailable.
try:
    from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore[import-untyped]

    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False
    logger.debug("scapy not installed; pcap parsing features will be unavailable")


@dataclass
class ConnectionInfo:
    """Describes a single observed network connection."""

    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""  # "tcp", "udp", etc.
    state: str = ""  # e.g. "ESTABLISHED", "LISTEN"


@dataclass
class NetworkCaptureResult:
    """Aggregated network capture analysis."""

    connections: list[ConnectionInfo] = field(default_factory=list)
    outbound_connections: list[ConnectionInfo] = field(default_factory=list)
    websocket_issues: list[str] = field(default_factory=list)
    pcap_packets: int = 0


class NetworkCapture:
    """Capture and analyse network traffic from a sandboxed container.

    The class works in two modes:

    1. **Inspect-based** -- extracts connection metadata from ``docker inspect``
       output and from commands executed inside the container.  This requires
       no additional dependencies.
    2. **Pcap-based** -- parses a pcap file produced by a tcpdump sidecar.
       This requires ``scapy`` to be installed.
    """

    def __init__(self, docker_manager: DockerManager) -> None:
        self._manager = docker_manager

    # ------------------------------------------------------------------
    # Inspect-based analysis
    # ------------------------------------------------------------------

    def parse_connections(self, container_inspect_data: dict[str, Any]) -> list[ConnectionInfo]:
        """Extract network connection information from ``docker inspect`` data.

        Parameters
        ----------
        container_inspect_data:
            The dictionary returned by ``container.attrs`` (i.e. the full
            ``docker inspect`` output for a container).

        Returns
        -------
        list[ConnectionInfo]
            Parsed connection descriptors.
        """
        connections: list[ConnectionInfo] = []

        network_settings = container_inspect_data.get("NetworkSettings", {})

        # Gateway / bridge IP
        gateway = network_settings.get("Gateway", "")
        ip_address = network_settings.get("IPAddress", "")

        # Published ports
        ports = network_settings.get("Ports", {}) or {}
        for port_proto, bindings in ports.items():
            port_str, proto = port_proto.split("/")
            conn = ConnectionInfo(
                source_ip=ip_address,
                destination_ip=gateway or "0.0.0.0",
                source_port=int(port_str),
                protocol=proto,
                state="LISTEN",
            )
            if bindings:
                conn.destination_port = int(bindings[0].get("HostPort", 0))
                conn.state = "PUBLISHED"
            connections.append(conn)

        # Per-network connections
        networks = network_settings.get("Networks", {}) or {}
        for net_name, net_info in networks.items():
            conn = ConnectionInfo(
                source_ip=net_info.get("IPAddress", ""),
                destination_ip=net_info.get("Gateway", ""),
                protocol="bridge",
                state="CONNECTED",
            )
            connections.append(conn)

        return connections

    def detect_outbound_connections(self) -> list[ConnectionInfo]:
        """Detect outbound network connections from the target container.

        Runs ``ss -tunp`` (or falls back to ``netstat -tunp``) inside the
        container to enumerate active sockets.

        Returns
        -------
        list[ConnectionInfo]
            Connections whose state indicates an outbound flow
            (``ESTABLISHED`` or ``SYN-SENT``).
        """
        outbound: list[ConnectionInfo] = []

        # Try ss first, fall back to netstat
        exit_code, output = self._exec_or_empty("ss -tunp")
        if exit_code != 0 or not output.strip():
            exit_code, output = self._exec_or_empty("netstat -tunp")

        if exit_code != 0:
            logger.warning("Unable to enumerate sockets inside target container")
            return outbound

        for line in output.splitlines():
            line = line.strip()
            # ss format:  State  Recv-Q  Send-Q  Local  Peer  Process
            # netstat format:  Proto  Recv-Q  Send-Q  Local  Foreign  State  PID/...
            if any(state in line.upper() for state in ("ESTAB", "SYN-SENT", "SYN_SENT")):
                conn = self._parse_socket_line(line)
                if conn is not None:
                    outbound.append(conn)

        logger.info("Detected %d outbound connections", len(outbound))
        return outbound

    def check_websocket_security(self) -> list[str]:
        """Check for WebSocket security issues inside the target container.

        Looks for common patterns that indicate missing Origin header
        validation in WebSocket server code.  This is a heuristic, not a
        definitive proof.

        Returns
        -------
        list[str]
            Human-readable descriptions of issues found.
        """
        issues: list[str] = []

        # Search for websocket-related files
        exit_code, output = self._exec_or_empty(
            "grep -r -l -i 'websocket\\|ws://' /app /srv /opt /home 2>/dev/null || true"
        )
        ws_files = [f for f in output.strip().splitlines() if f]

        if not ws_files:
            logger.debug("No WebSocket files detected")
            return issues

        for ws_file in ws_files[:20]:  # cap to avoid runaway scanning
            exit_code, content = self._exec_or_empty(f"cat {ws_file}")
            if exit_code != 0:
                continue

            lower_content = content.lower()

            # Check for WebSocket server that does not validate Origin
            if "websocket" in lower_content or "ws://" in lower_content:
                has_origin_check = any(
                    pattern in lower_content
                    for pattern in (
                        "origin",
                        "check_origin",
                        "allowed_origins",
                        "cors",
                        "verify_origin",
                    )
                )
                if not has_origin_check:
                    issues.append(
                        f"WebSocket handler in {ws_file} does not appear to "
                        f"validate the Origin header, risking Cross-Site "
                        f"WebSocket Hijacking (CSWSH)."
                    )

            # Insecure ws:// instead of wss://
            if "ws://" in content and "wss://" not in content:
                issues.append(
                    f"File {ws_file} uses unencrypted ws:// scheme. "
                    f"Consider using wss:// for transport-layer security."
                )

        if issues:
            logger.warning("WebSocket security issues found: %d", len(issues))
        return issues

    # ------------------------------------------------------------------
    # Pcap-based analysis (requires scapy)
    # ------------------------------------------------------------------

    def parse_pcap(self, pcap_path: str) -> NetworkCaptureResult:
        """Parse a pcap capture file and return aggregated results.

        Parameters
        ----------
        pcap_path:
            Filesystem path to the ``.pcap`` file (on the host).

        Returns
        -------
        NetworkCaptureResult
            Aggregated network capture analysis.

        Raises
        ------
        DockerError
            If scapy is not installed.
        """
        if not _HAS_SCAPY:
            raise DockerError(
                "scapy is required for pcap parsing. "
                "Install it with: pip install scapy"
            )

        result = NetworkCaptureResult()

        try:
            packets = rdpcap(pcap_path)
        except Exception as exc:
            logger.error("Failed to read pcap file %s: %s", pcap_path, exc)
            return result

        result.pcap_packets = len(packets)

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            conn = ConnectionInfo(
                source_ip=ip.src,
                destination_ip=ip.dst,
            )
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                conn.source_port = tcp.sport
                conn.destination_port = tcp.dport
                conn.protocol = "tcp"
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                conn.source_port = udp.sport
                conn.destination_port = udp.dport
                conn.protocol = "udp"
            else:
                conn.protocol = str(ip.proto)

            result.connections.append(conn)

        # Deduplicate and classify outbound (non-private destination)
        seen: set[tuple[str, str, int, int, str]] = set()
        for conn in result.connections:
            key = (conn.source_ip, conn.destination_ip, conn.source_port, conn.destination_port, conn.protocol)
            if key not in seen and not _is_private_ip(conn.destination_ip):
                result.outbound_connections.append(conn)
                seen.add(key)

        logger.info(
            "Parsed %d packets, %d connections, %d outbound",
            result.pcap_packets,
            len(result.connections),
            len(result.outbound_connections),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _exec_or_empty(self, command: str) -> tuple[int, str]:
        """Execute a command in the target, returning (exit_code, output).

        Returns ``(1, "")`` if there is no running target container.
        """
        try:
            return self._manager.exec_in_target(command)
        except DockerError:
            return 1, ""

    @staticmethod
    def _parse_socket_line(line: str) -> ConnectionInfo | None:
        """Best-effort parsing of a single ``ss`` or ``netstat`` output line."""
        # Example ss line:
        #   ESTAB  0  0  10.0.0.2:45678  93.184.216.34:443
        parts = line.split()
        if len(parts) < 5:
            return None

        state = parts[0].upper()
        # Heuristic: local address is typically parts[3], peer is parts[4]
        local = parts[3] if len(parts) > 3 else ""
        peer = parts[4] if len(parts) > 4 else ""

        src_ip, src_port = _split_address(local)
        dst_ip, dst_port = _split_address(peer)

        if not dst_ip:
            return None

        # Determine protocol from the line
        proto = "tcp"
        lower = line.lower()
        if "udp" in lower:
            proto = "udp"

        return ConnectionInfo(
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            state=state,
        )


def _split_address(addr: str) -> tuple[str, int]:
    """Split ``host:port`` into ``(host, port)``, handling IPv6 brackets."""
    if not addr:
        return "", 0
    # IPv6: [::1]:8080
    if addr.startswith("["):
        bracket_end = addr.rfind("]")
        if bracket_end == -1:
            return addr, 0
        host = addr[1:bracket_end]
        port_str = addr[bracket_end + 2:]  # skip ]:
        try:
            return host, int(port_str)
        except ValueError:
            return host, 0
    # IPv4: 10.0.0.2:443
    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return parts[0], 0
    return addr, 0


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a private / reserved range (RFC 1918 + loopback)."""
    _PRIVATE_PREFIXES = (
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",
        "0.",
        "169.254.",
    )
    return ip.startswith(_PRIVATE_PREFIXES) or ip == "::1" or ip == "fe80::"
