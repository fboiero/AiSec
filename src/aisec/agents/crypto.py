"""Cryptographic security analysis agent."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weak cipher / algorithm constants
# ---------------------------------------------------------------------------

WEAK_CIPHERS: set[str] = {
    "RC4",
    "DES",
    "3DES",
    "DES-CBC3",
    "NULL",
    "EXPORT",
    "anon",
    "eNULL",
    "aNULL",
    "RC2",
    "IDEA",
    "SEED",
}

WEAK_CIPHER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(?:RC4|DES(?!-CBC3)|DES-CBC3|3DES|NULL|EXPORT|eNULL|aNULL|RC2)\b"),
    re.compile(r"(?i)\bMD5WithRSA\b"),
    re.compile(r"(?i)\bSSLv[23]\b"),
    re.compile(r"(?i)\bTLSv1(?:\.0)?\b"),
]

# Patterns for detecting weak / deprecated algorithms in source code and configs
WEAK_ALGORITHM_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?i)\bmd5\b"), "MD5", "Use SHA-256 or SHA-3 instead of MD5."),
    (re.compile(r"(?i)\bsha[\-_]?1\b"), "SHA-1", "Use SHA-256 or SHA-3 instead of SHA-1."),
    (re.compile(r"(?i)\bdes[\-_]?cbc\b"), "DES-CBC", "Use AES-256-GCM instead of DES."),
    (re.compile(r"(?i)\brc4\b"), "RC4", "Use AES-256-GCM or ChaCha20-Poly1305 instead of RC4."),
    (re.compile(r"(?i)\bblowfish\b"), "Blowfish", "Use AES-256-GCM instead of Blowfish."),
    (re.compile(r"(?i)\bECB\b"), "ECB mode", "Use GCM or CBC mode with HMAC instead of ECB."),
]

# Regex patterns for hardcoded secrets and crypto keys
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private key (PEM)"),
    (re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Encrypted private key (PEM)"),
    (re.compile(r"(?i)(?:secret[_-]?key|private[_-]?key|encryption[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Hardcoded crypto key"),
    (re.compile(r"(?i)(?:aes|des|hmac)[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Hardcoded symmetric key"),
    (re.compile(r"(?i)(?:passphrase|key_password)\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "Hardcoded key passphrase"),
    (re.compile(r"[0-9a-fA-F]{64}"), "Potential hex-encoded 256-bit key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI API key"),
]

# Weak PRNG patterns (Python-specific)
WEAK_PRNG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\brandom\.random\s*\("), "random.random()"),
    (re.compile(r"\brandom\.randint\s*\("), "random.randint()"),
    (re.compile(r"\brandom\.choice\s*\("), "random.choice()"),
    (re.compile(r"\brandom\.randrange\s*\("), "random.randrange()"),
    (re.compile(r"\brandom\.sample\s*\("), "random.sample()"),
    (re.compile(r"\brandom\.getrandbits\s*\("), "random.getrandbits()"),
    (re.compile(r"\brandom\.uniform\s*\("), "random.uniform()"),
    (re.compile(r"\brandom\.shuffle\s*\("), "random.shuffle()"),
]

# HTTP service ports where HSTS applies
HTTP_SERVICE_PORTS: set[int] = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000}

# Quantum-vulnerable algorithm families
PQC_VULNERABLE_ALGORITHMS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?i)\bRSA\b"), "RSA",
     "Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key encapsulation."),
    (re.compile(r"(?i)\b(?:ECDSA|ECDH|EC[_-]?KEY|secp\d+|prime256v1|P-256|P-384|P-521)\b"), "ECC",
     "Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange."),
    (re.compile(r"(?i)\b(?:DH|Diffie[\-_]?Hellman|DHE|ECDHE)\b"), "Diffie-Hellman",
     "Migrate to ML-KEM (FIPS 203) for post-quantum key encapsulation."),
    (re.compile(r"(?i)\bDSA\b"), "DSA",
     "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for post-quantum signatures."),
]


class CryptoAuditAgent(BaseAgent):
    """Audit cryptographic configuration, certificate hygiene, and key management."""

    name: ClassVar[str] = "crypto"
    description: ClassVar[str] = (
        "Analyses TLS/SSL configuration, certificate validity, cipher suite strength, "
        "key lengths, HSTS headers, encryption at rest, hardcoded secrets, weak "
        "algorithms, PRNG usage, and post-quantum cryptography readiness."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM02", "LLM09", "ASI07", "ASI04"]
    depends_on: ClassVar[list[str]] = ["network"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all cryptographic security checks."""
        container_info = await self._get_container_info()

        await self._check_tls_configuration(container_info)
        await self._check_certificate_validation()
        await self._check_cipher_suite_strength(container_info)
        await self._check_key_lengths()
        await self._check_hsts_header(container_info)
        await self._check_encryption_at_rest()
        await self._check_hardcoded_keys()
        await self._check_algorithm_weakness()
        await self._check_quantum_readiness()
        await self._check_weak_prng()

    # ------------------------------------------------------------------
    # Container introspection helpers
    # ------------------------------------------------------------------

    async def _get_container_info(self) -> dict[str, Any] | None:
        """Return docker inspect output for the target container."""
        dm = self.context.docker_manager
        if dm is not None:
            try:
                return await dm.inspect_container(self.context.container_id)  # type: ignore[union-attr]
            except Exception:
                logger.debug("docker_manager.inspect_container failed; trying CLI")
        return await self._inspect_via_cli()

    async def _inspect_via_cli(self) -> dict[str, Any] | None:
        cid = self.context.container_id
        if not cid:
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return None
            data = json.loads(stdout)
            return data[0] if isinstance(data, list) else data
        except Exception:
            return None

    async def _exec_in_container(self, command: str) -> str:
        """Run a shell command inside the target container and return stdout."""
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # 1. TLS / SSL Configuration
    # ------------------------------------------------------------------

    async def _check_tls_configuration(self, info: dict[str, Any] | None) -> None:
        """Inspect TLS version and cipher suite configuration."""
        cid = self.context.container_id
        if not cid:
            return

        # Gather TLS-related config snippets from common locations
        tls_config = await self._exec_in_container(
            "cat /etc/ssl/openssl.cnf 2>/dev/null; "
            "cat /etc/nginx/nginx.conf 2>/dev/null; "
            "cat /etc/apache2/sites-enabled/*.conf 2>/dev/null; "
            "cat /etc/httpd/conf.d/ssl.conf 2>/dev/null; "
            "cat /app/*.conf 2>/dev/null | head -500"
        )

        # Check openssl version inside the container
        openssl_version = await self._exec_in_container("openssl version 2>/dev/null")

        # Detect TLS version settings
        tls_version_issues: list[str] = []
        if tls_config:
            if re.search(r"(?i)SSLv2|ssl_protocols\s+.*SSLv2", tls_config):
                tls_version_issues.append("SSLv2 enabled (completely broken)")
            if re.search(r"(?i)SSLv3|ssl_protocols\s+.*SSLv3", tls_config):
                tls_version_issues.append("SSLv3 enabled (vulnerable to POODLE)")
            if re.search(r"(?i)TLSv1(?:\.0)?(?!\.\d)|ssl_protocols\s+.*TLSv1(?!\.\d)", tls_config):
                tls_version_issues.append("TLS 1.0 enabled (deprecated, PCI-DSS non-compliant)")
            if re.search(r"(?i)TLSv1\.1|ssl_protocols\s+.*TLSv1\.1", tls_config):
                tls_version_issues.append("TLS 1.1 enabled (deprecated)")

        if tls_version_issues:
            self.add_finding(
                title="Insecure TLS/SSL protocol versions enabled",
                description=(
                    "The container's TLS configuration allows deprecated or broken "
                    f"protocol versions: {'; '.join(tls_version_issues)}. "
                    "These protocols are vulnerable to known attacks and should be "
                    "disabled in favour of TLS 1.2+ only."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Deprecated TLS versions detected",
                        raw_data="\n".join(f"  - {issue}" for issue in tls_version_issues),
                        location=f"container:{cid}",
                    ),
                    *(
                        [Evidence(
                            type="config",
                            summary="OpenSSL version",
                            raw_data=openssl_version,
                            location=f"container:{cid}",
                        )]
                        if openssl_version else []
                    ),
                ],
                remediation=(
                    "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Configure the "
                    "server to support only TLS 1.2 and TLS 1.3. For nginx: "
                    "'ssl_protocols TLSv1.2 TLSv1.3;'. Update OpenSSL to a "
                    "current supported version."
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc8996",
                ],
                cvss_score=9.1,
            )

        # Optionally try sslyze for deeper analysis
        await self._try_sslyze_scan(info)

    async def _try_sslyze_scan(self, info: dict[str, Any] | None) -> None:
        """Attempt an SSLyze scan against exposed HTTPS ports."""
        try:
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("SSLyze not installed; skipping deep TLS analysis")
            return

        if info is None:
            return

        ports_map: dict[str, Any] = info.get("NetworkSettings", {}).get("Ports") or {}
        tls_ports = [
            int(p.split("/")[0]) for p in ports_map
            if int(p.split("/")[0]) in (443, 8443)
        ]
        if not tls_ports:
            return

        try:
            scanner = Scanner()
            for port in tls_ports:
                request = ServerScanRequest(
                    server_location=ServerNetworkLocation(hostname="127.0.0.1", port=port)
                )
                scanner.queue_scans([request])

            for result in scanner.get_results():
                if result.scan_result and result.scan_result.ssl_2_0_cipher_suites:
                    accepted = result.scan_result.ssl_2_0_cipher_suites.result
                    if accepted and accepted.accepted_cipher_suites:
                        self.add_finding(
                            title="SSLyze detected SSLv2 cipher suites accepted",
                            description="SSLyze confirmed the server accepts SSLv2 connections.",
                            severity=Severity.CRITICAL,
                            owasp_llm=["LLM09"],
                            owasp_agentic=["ASI07"],
                            nist_ai_rmf=["MEASURE"],
                            evidence=[Evidence(
                                type="network_capture",
                                summary="SSLyze SSLv2 scan",
                                raw_data=str(accepted.accepted_cipher_suites)[:2000],
                            )],
                            remediation="Disable SSLv2 immediately.",
                            cvss_score=9.8,
                        )
        except Exception as exc:
            logger.debug("SSLyze scan failed: %s", exc)

    # ------------------------------------------------------------------
    # 2. Certificate Validation
    # ------------------------------------------------------------------

    async def _check_certificate_validation(self) -> None:
        """Inspect certificates for expiry, self-signed status, and chain issues."""
        cid = self.context.container_id
        if not cid:
            return

        cert_files = await self._exec_in_container(
            "find / -maxdepth 5 \\( -name '*.pem' -o -name '*.crt' -o -name '*.cer' \\) "
            "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -30"
        )
        if not cert_files:
            return

        for cert_path in cert_files.splitlines():
            cert_path = cert_path.strip()
            if not cert_path:
                continue

            # Parse certificate details with openssl
            cert_text = await self._exec_in_container(
                f"openssl x509 -in '{cert_path}' -noout -text -dates -issuer -subject 2>/dev/null"
            )
            if not cert_text:
                continue

            issues: list[str] = []

            # Check for self-signed certificates
            issuer_match = re.search(r"Issuer:\s*(.+)", cert_text)
            subject_match = re.search(r"Subject:\s*(.+)", cert_text)
            if issuer_match and subject_match:
                issuer = issuer_match.group(1).strip()
                subject = subject_match.group(1).strip()
                if issuer == subject:
                    issues.append("Certificate is self-signed")

            # Check expiry
            not_after_match = re.search(r"notAfter=(.+)", cert_text)
            if not_after_match:
                not_after_str = not_after_match.group(1).strip()
                # Check using openssl to avoid date parsing complexities
                expiry_check = await self._exec_in_container(
                    f"openssl x509 -in '{cert_path}' -checkend 0 2>/dev/null; echo $?"
                )
                if "Certificate will expire" in expiry_check or expiry_check.strip().endswith("1"):
                    issues.append(f"Certificate has expired (notAfter={not_after_str})")
                else:
                    # Check if expiring within 30 days
                    near_expiry = await self._exec_in_container(
                        f"openssl x509 -in '{cert_path}' -checkend 2592000 2>/dev/null; echo $?"
                    )
                    if "Certificate will expire" in near_expiry or near_expiry.strip().endswith("1"):
                        issues.append(f"Certificate expires within 30 days (notAfter={not_after_str})")

            # Check signature algorithm
            sig_match = re.search(r"Signature Algorithm:\s*(\S+)", cert_text)
            if sig_match:
                sig_algo = sig_match.group(1)
                if "md5" in sig_algo.lower():
                    issues.append(f"Certificate uses weak signature algorithm: {sig_algo}")
                elif "sha1" in sig_algo.lower():
                    issues.append(f"Certificate uses deprecated signature algorithm: {sig_algo}")

            if issues:
                severity = Severity.CRITICAL if any("expired" in i.lower() for i in issues) else Severity.HIGH
                self.add_finding(
                    title=f"Certificate issue: {cert_path}",
                    description=(
                        f"Certificate at '{cert_path}' has the following issues: "
                        f"{'; '.join(issues)}. Improper certificate management can "
                        "lead to man-in-the-middle attacks, data interception, and "
                        "trust chain failures."
                    ),
                    severity=severity,
                    owasp_llm=["LLM02"],
                    owasp_agentic=["ASI07"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary="Certificate analysis",
                            raw_data=cert_text[:2000],
                            location=f"container:{cid}:{cert_path}",
                        )
                    ],
                    remediation=(
                        "Replace expired or self-signed certificates with certificates "
                        "issued by a trusted CA. Use automated renewal (e.g., Let's "
                        "Encrypt / certbot). Ensure the full certificate chain is "
                        "configured. Use SHA-256 or stronger signature algorithms."
                    ),
                    cvss_score=8.0 if severity == Severity.CRITICAL else 6.5,
                )

    # ------------------------------------------------------------------
    # 3. Cipher Suite Strength
    # ------------------------------------------------------------------

    async def _check_cipher_suite_strength(self, info: dict[str, Any] | None) -> None:
        """Detect weak cipher suites in server configurations."""
        cid = self.context.container_id
        if not cid:
            return

        # Gather cipher configuration from common locations
        cipher_config = await self._exec_in_container(
            "grep -r -i 'ssl_ciphers\\|SSLCipherSuite\\|ciphers\\|cipher_list' "
            "/etc/nginx /etc/apache2 /etc/httpd /app /etc/ssl 2>/dev/null | head -50"
        )

        # Also check openssl default ciphers
        default_ciphers = await self._exec_in_container(
            "openssl ciphers -v 'ALL' 2>/dev/null | head -100"
        )

        weak_found: list[tuple[str, str]] = []  # (cipher_name, location)

        if cipher_config:
            for line in cipher_config.splitlines():
                for pattern in WEAK_CIPHER_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        weak_found.append((match.group(0), line.split(":")[0] if ":" in line else "config"))

        if default_ciphers:
            for line in default_ciphers.splitlines():
                parts = line.split()
                if not parts:
                    continue
                cipher_name = parts[0]
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        weak_found.append((cipher_name, "openssl defaults"))
                        break

        if weak_found:
            # Deduplicate
            unique_ciphers = sorted({name for name, _ in weak_found})
            details = "\n".join(f"  - {name} (in {loc})" for name, loc in weak_found[:30])
            self.add_finding(
                title=f"Weak cipher suites detected ({len(unique_ciphers)} ciphers)",
                description=(
                    f"Found {len(unique_ciphers)} weak or deprecated cipher suite(s): "
                    f"{', '.join(unique_ciphers[:10])}. Weak ciphers are susceptible "
                    "to cryptanalytic attacks and may allow an adversary to decrypt "
                    "intercepted traffic containing sensitive AI model data, prompts, "
                    "or API credentials."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(unique_ciphers)} weak ciphers",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Remove all weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, "
                    "MD5-based MACs). Configure strong cipher suites only, preferring "
                    "AEAD ciphers: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, "
                    "ECDHE-ECDSA-AES256-GCM-SHA384. For nginx: "
                    "'ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!DES:!3DES;'."
                ),
                references=[
                    "https://wiki.mozilla.org/Security/Server_Side_TLS",
                ],
                cvss_score=7.4,
            )

    # ------------------------------------------------------------------
    # 4. Key Length Assessment
    # ------------------------------------------------------------------

    async def _check_key_lengths(self) -> None:
        """Flag RSA keys < 2048 bits and ECC keys < 256 bits."""
        cid = self.context.container_id
        if not cid:
            return

        key_files = await self._exec_in_container(
            "find / -maxdepth 5 \\( -name '*.key' -o -name '*.pem' -o -name '*.crt' \\) "
            "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -30"
        )
        if not key_files:
            return

        weak_keys: list[tuple[str, str, int]] = []  # (path, type, bits)

        for key_path in key_files.splitlines():
            key_path = key_path.strip()
            if not key_path:
                continue

            # Try to extract RSA key size
            rsa_info = await self._exec_in_container(
                f"openssl rsa -in '{key_path}' -text -noout 2>/dev/null | head -5"
            )
            if rsa_info:
                bits_match = re.search(r"(\d+)\s*bit", rsa_info)
                if bits_match:
                    bits = int(bits_match.group(1))
                    if bits < 2048:
                        weak_keys.append((key_path, "RSA", bits))
                continue

            # Try to extract EC key size
            ec_info = await self._exec_in_container(
                f"openssl ec -in '{key_path}' -text -noout 2>/dev/null | head -5"
            )
            if ec_info:
                bits_match = re.search(r"(\d+)\s*bit", ec_info)
                if bits_match:
                    bits = int(bits_match.group(1))
                    if bits < 256:
                        weak_keys.append((key_path, "ECC", bits))
                continue

            # Try parsing as x509 certificate for public key info
            cert_key_info = await self._exec_in_container(
                f"openssl x509 -in '{key_path}' -noout -text 2>/dev/null | grep -A1 'Public-Key:'"
            )
            if cert_key_info:
                bits_match = re.search(r"\((\d+)\s*bit\)", cert_key_info)
                if bits_match:
                    bits = int(bits_match.group(1))
                    key_type = "RSA" if "RSA" in cert_key_info.upper() else "ECC"
                    min_bits = 2048 if key_type == "RSA" else 256
                    if bits < min_bits:
                        weak_keys.append((key_path, key_type, bits))

        if weak_keys:
            details = "\n".join(
                f"  - {path}: {ktype} {bits}-bit (minimum: {'2048' if ktype == 'RSA' else '256'})"
                for path, ktype, bits in weak_keys
            )
            self.add_finding(
                title=f"Weak cryptographic key lengths ({len(weak_keys)} keys)",
                description=(
                    f"Found {len(weak_keys)} cryptographic key(s) with insufficient "
                    "key lengths. Short keys are vulnerable to brute-force attacks "
                    "and do not meet current security standards (NIST SP 800-57)."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Weak key lengths",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Regenerate all keys with adequate lengths: RSA >= 2048 bits "
                    "(3072 or 4096 recommended), ECC >= 256 bits (P-384 or P-521 "
                    "recommended). Rotate all certificates using the new keys."
                ),
                references=[
                    "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final",
                ],
                cvss_score=7.5,
            )

    # ------------------------------------------------------------------
    # 5. HSTS Header
    # ------------------------------------------------------------------

    async def _check_hsts_header(self, info: dict[str, Any] | None) -> None:
        """Check for Strict-Transport-Security header on HTTP service ports."""
        cid = self.context.container_id
        if not cid or info is None:
            return

        ports_map: dict[str, Any] = info.get("NetworkSettings", {}).get("Ports") or {}
        http_ports = [
            int(p.split("/")[0]) for p in ports_map
            if int(p.split("/")[0]) in HTTP_SERVICE_PORTS
        ]
        if not http_ports:
            return

        missing_hsts_ports: list[int] = []
        weak_hsts_ports: list[tuple[int, str]] = []

        for port in http_ports:
            # Try to fetch headers from inside the container (loopback)
            response = await self._exec_in_container(
                f"curl -skI --max-time 5 http://127.0.0.1:{port}/ 2>/dev/null; "
                f"curl -skI --max-time 5 https://127.0.0.1:{port}/ 2>/dev/null"
            )
            if not response:
                # curl may not be available; try wget
                response = await self._exec_in_container(
                    f"wget -qS --no-check-certificate --timeout=5 -O /dev/null "
                    f"http://127.0.0.1:{port}/ 2>&1 | head -30; "
                    f"wget -qS --no-check-certificate --timeout=5 -O /dev/null "
                    f"https://127.0.0.1:{port}/ 2>&1 | head -30"
                )

            if not response:
                continue

            hsts_match = re.search(r"(?i)strict-transport-security:\s*(.+)", response)
            if not hsts_match:
                missing_hsts_ports.append(port)
            else:
                hsts_value = hsts_match.group(1).strip()
                max_age_match = re.search(r"max-age=(\d+)", hsts_value)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        weak_hsts_ports.append((port, hsts_value))

        if missing_hsts_ports:
            self.add_finding(
                title=f"Missing HSTS header on {len(missing_hsts_ports)} port(s)",
                description=(
                    f"HTTP service ports {missing_hsts_ports} do not return a "
                    "Strict-Transport-Security header. Without HSTS, clients may "
                    "connect over unencrypted HTTP, exposing AI agent communications "
                    "to interception and downgrade attacks."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Ports missing HSTS",
                        raw_data=json.dumps({"ports_missing_hsts": missing_hsts_ports}),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Add the Strict-Transport-Security header to all HTTPS responses: "
                    "'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
                    "preload'. Ensure HTTP redirects to HTTPS before the header is served."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ],
                cvss_score=5.4,
            )

        if weak_hsts_ports:
            details = "\n".join(f"  - Port {port}: {value}" for port, value in weak_hsts_ports)
            self.add_finding(
                title="Weak HSTS configuration (short max-age)",
                description=(
                    "HSTS header is present but with a max-age shorter than the "
                    "recommended 1 year (31536000 seconds). A short max-age weakens "
                    "HSTS protection by allowing downgrade attacks between renewals."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Weak HSTS max-age",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Increase the HSTS max-age to at least 31536000 (1 year). "
                    "Add 'includeSubDomains' and consider HSTS preloading."
                ),
                cvss_score=3.5,
            )

    # ------------------------------------------------------------------
    # 6. Encryption at Rest
    # ------------------------------------------------------------------

    async def _check_encryption_at_rest(self) -> None:
        """Check mount points and data directories for unencrypted storage."""
        cid = self.context.container_id
        if not cid:
            return

        # Check mount points
        mounts = await self._exec_in_container("mount 2>/dev/null")
        df_output = await self._exec_in_container("df -h 2>/dev/null")

        # Look for tmpfs and encrypted volumes vs regular bind mounts
        bind_mounts = await self._exec_in_container(
            "cat /proc/self/mountinfo 2>/dev/null | grep -v 'proc\\|sys\\|tmpfs\\|cgroup' | head -30"
        )

        # Check for common data directories
        data_dirs = await self._exec_in_container(
            "ls -la /data /var/lib /var/data /app/data /models /app/models "
            "/tmp /var/tmp 2>/dev/null | head -50"
        )

        # Detect volume mounts without encryption from docker inspect
        container_info = await self._get_container_info()
        unencrypted_mounts: list[str] = []

        if container_info:
            mounts_list = container_info.get("Mounts", [])
            for mount in mounts_list:
                mount_type = mount.get("Type", "")
                source = mount.get("Source", "")
                dest = mount.get("Destination", "")
                driver = mount.get("Driver", "")

                # Flag bind mounts to sensitive directories (no encryption guarantee)
                if mount_type == "bind":
                    unencrypted_mounts.append(
                        f"Bind mount: {source} -> {dest} (no encryption enforced)"
                    )
                elif mount_type == "volume" and driver in ("local", ""):
                    unencrypted_mounts.append(
                        f"Local volume: {source} -> {dest} (default driver, no encryption)"
                    )

        # Check for unencrypted sensitive files in common locations
        sensitive_files = await self._exec_in_container(
            "find /data /var/lib /app/data /models /app/models "
            "-maxdepth 3 -type f \\( -name '*.db' -o -name '*.sqlite' "
            "-o -name '*.json' -o -name '*.csv' -o -name '*.pkl' "
            "-o -name '*.pt' -o -name '*.onnx' -o -name '*.bin' \\) "
            "2>/dev/null | head -20"
        )

        issues: list[str] = list(unencrypted_mounts)
        if sensitive_files:
            file_count = len(sensitive_files.strip().splitlines())
            issues.append(
                f"{file_count} sensitive data file(s) found in unencrypted storage"
            )

        if issues:
            raw = "\n".join(f"  - {i}" for i in issues)
            self.add_finding(
                title=f"Unencrypted data storage detected ({len(issues)} issues)",
                description=(
                    "The container uses storage volumes or directories without "
                    "apparent encryption at rest. AI model weights, training data, "
                    "embeddings, and user data stored without encryption are at risk "
                    "of exposure if the host or storage media is compromised."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Unencrypted storage",
                        raw_data=raw,
                        location=f"container:{cid}",
                    ),
                    *(
                        [Evidence(
                            type="file_content",
                            summary="Sensitive data files",
                            raw_data=sensitive_files[:2000],
                            location=f"container:{cid}",
                        )]
                        if sensitive_files else []
                    ),
                ],
                remediation=(
                    "Enable encryption at rest for all volumes containing sensitive "
                    "data. Use LUKS-encrypted volumes, Docker volume plugins with "
                    "encryption support (e.g., docker-volume-crypt), or cloud-managed "
                    "encrypted storage (e.g., AWS EBS encryption, GCP CMEK). For "
                    "application-level protection, encrypt sensitive data fields before "
                    "writing to disk."
                ),
                cvss_score=5.5,
            )

    # ------------------------------------------------------------------
    # 7. Hardcoded Keys / Secrets
    # ------------------------------------------------------------------

    async def _check_hardcoded_keys(self) -> None:
        """Scan container filesystem for hardcoded cryptographic keys and secrets."""
        cid = self.context.container_id
        if not cid:
            return

        # Search for private keys and hardcoded secrets in source and config files
        scan_output = await self._exec_in_container(
            "grep -r -l '\\-\\-\\-\\-\\-BEGIN.*PRIVATE KEY' "
            "/app /src /opt /etc /home 2>/dev/null | "
            "grep -v '/proc\\|/sys\\|node_modules\\|.git' | head -20"
        )

        # Search for hardcoded secrets using regex in source files
        secret_scan = await self._exec_in_container(
            "grep -r -n -E "
            "'(secret[_-]?key|private[_-]?key|encryption[_-]?key|aes[_-]?key|hmac[_-]?key)"
            "\\s*[:=]\\s*[\\x27\"][^\\x27\"]{8,}[\\x27\"]' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|example\\|test\\|mock' | head -30"
        )

        # Search for hex-encoded keys (64+ hex chars suggesting 256-bit keys)
        hex_keys = await self._exec_in_container(
            "grep -r -n -E '[0-9a-fA-F]{64,}' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc\\|lock\\|sum\\|hash' | head -20"
        )

        findings_data: list[tuple[str, str]] = []  # (label, raw_data)

        if scan_output:
            findings_data.append(("Private key files", scan_output))

        if secret_scan:
            # Mask actual secret values
            masked_lines: list[str] = []
            for line in secret_scan.splitlines():
                # Keep file path and key name but mask the value
                masked = re.sub(
                    r'([:=]\s*["\'])([^"\']{4})[^"\']*(["\'])',
                    r'\1\2****\3',
                    line,
                )
                masked_lines.append(masked)
            findings_data.append(("Hardcoded secrets", "\n".join(masked_lines)))

        if hex_keys:
            # Only keep plausible matches (ignore hashes in lock files, etc.)
            plausible = [
                line for line in hex_keys.splitlines()
                if not any(ext in line.lower() for ext in (".lock", ".sum", "checksum", "sha256"))
            ]
            if plausible:
                findings_data.append(("Potential hex-encoded keys", "\n".join(plausible[:10])))

        if findings_data:
            evidence_items = [
                Evidence(
                    type="file_content",
                    summary=label,
                    raw_data=data[:2000],
                    location=f"container:{cid}",
                )
                for label, data in findings_data
            ]
            total_hits = sum(len(data.splitlines()) for _, data in findings_data)
            self.add_finding(
                title=f"Hardcoded cryptographic keys or secrets ({total_hits} occurrences)",
                description=(
                    f"Found {total_hits} potential hardcoded cryptographic key(s) or "
                    "secret(s) in the container filesystem. Hardcoded keys can be "
                    "extracted by anyone with access to the container image, enabling "
                    "decryption of protected data, impersonation, or unauthorized "
                    "access to external services."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MEASURE"],
                evidence=evidence_items,
                remediation=(
                    "Remove all hardcoded keys and secrets from source code and "
                    "configuration files. Use environment variables, a secrets "
                    "manager (e.g., HashiCorp Vault, AWS Secrets Manager), or "
                    "Docker secrets for runtime injection. Rotate all exposed "
                    "keys and credentials immediately."
                ),
                cvss_score=9.0,
                ai_risk_score=8.5,
            )

    # ------------------------------------------------------------------
    # 8. Algorithm Weakness Detection
    # ------------------------------------------------------------------

    async def _check_algorithm_weakness(self) -> None:
        """Detect usage of MD5, SHA-1, DES, RC4 in code files and configs."""
        cid = self.context.container_id
        if not cid:
            return

        # Search for weak algorithm usage in source code
        algo_scan = await self._exec_in_container(
            "grep -r -n -i -E '\\b(md5|sha1|sha-1|des-cbc|rc4|blowfish|ECB)\\b' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc\\|checksum\\|test' | head -50"
        )

        if not algo_scan:
            return

        detected_algorithms: dict[str, list[str]] = {}  # algo -> list of file:line

        for line in algo_scan.splitlines():
            line = line.strip()
            if not line:
                continue
            for pattern, algo_name, _remediation in WEAK_ALGORITHM_PATTERNS:
                if pattern.search(line):
                    detected_algorithms.setdefault(algo_name, []).append(line)
                    break

        if not detected_algorithms:
            return

        total_usages = sum(len(locs) for locs in detected_algorithms.values())
        algo_summary = ", ".join(
            f"{name} ({len(locs)}x)" for name, locs in detected_algorithms.items()
        )
        details_lines: list[str] = []
        for algo_name, locations in detected_algorithms.items():
            details_lines.append(f"  [{algo_name}]")
            for loc in locations[:5]:
                details_lines.append(f"    {loc[:200]}")

        # Build remediation from individual algorithm recommendations
        remediations = []
        seen_algos: set[str] = set()
        for _, algo_name, algo_remed in WEAK_ALGORITHM_PATTERNS:
            if algo_name in detected_algorithms and algo_name not in seen_algos:
                remediations.append(algo_remed)
                seen_algos.add(algo_name)

        self.add_finding(
            title=f"Weak cryptographic algorithms in use ({total_usages} occurrences)",
            description=(
                f"Detected {total_usages} usage(s) of weak or deprecated cryptographic "
                f"algorithms: {algo_summary}. These algorithms have known vulnerabilities "
                "and should not be used for security-sensitive operations such as "
                "hashing credentials, signing data, or encrypting AI model communications."
            ),
            severity=Severity.HIGH,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI07"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Weak algorithm usage: {algo_summary}",
                    raw_data="\n".join(details_lines)[:2000],
                    location=f"container:{cid}",
                )
            ],
            remediation=" ".join(remediations) if remediations else (
                "Replace all weak algorithms: use SHA-256/SHA-3 instead of MD5/SHA-1, "
                "AES-256-GCM instead of DES/RC4/Blowfish, and avoid ECB mode."
            ),
            references=[
                "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
            ],
            cvss_score=6.5,
        )

    # ------------------------------------------------------------------
    # 9. Quantum Readiness Advisory
    # ------------------------------------------------------------------

    async def _check_quantum_readiness(self) -> None:
        """Inventory RSA/ECC/DH usage and advise on post-quantum migration."""
        cid = self.context.container_id
        if not cid:
            return

        # Scan for quantum-vulnerable algorithm references
        pqc_scan = await self._exec_in_container(
            "grep -r -n -i -E '\\b(RSA|ECDSA|ECDH|EC_KEY|secp[0-9]+|prime256v1|"
            "P-256|P-384|P-521|DH|DHE|ECDHE|Diffie.Hellman|DSA)\\b' "
            "/app /src /opt /etc/ssl /etc/nginx /etc/apache2 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc' | head -50"
        )

        # Also check certificate files for algorithm types
        cert_algos = await self._exec_in_container(
            "find / -maxdepth 5 \\( -name '*.pem' -o -name '*.crt' -o -name '*.key' \\) "
            "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20 | "
            "while read f; do "
            "  echo \"$f: $(openssl x509 -in \"$f\" -noout -text 2>/dev/null | "
            "  grep -E 'Public Key Algorithm|Signature Algorithm' | head -2)\"; "
            "done"
        )

        inventory: dict[str, list[str]] = {}  # algo_family -> list of locations

        for scan_data in (pqc_scan, cert_algos):
            if not scan_data:
                continue
            for line in scan_data.splitlines():
                line = line.strip()
                if not line:
                    continue
                for pattern, algo_family, _advice in PQC_VULNERABLE_ALGORITHMS:
                    if pattern.search(line):
                        inventory.setdefault(algo_family, []).append(line)
                        break

        if not inventory:
            return

        total_refs = sum(len(locs) for locs in inventory.values())
        algo_summary = ", ".join(
            f"{name} ({len(locs)} refs)" for name, locs in inventory.items()
        )

        # Build migration advice per algorithm family
        migration_lines: list[str] = []
        seen_families: set[str] = set()
        for _, family, advice in PQC_VULNERABLE_ALGORITHMS:
            if family in inventory and family not in seen_families:
                migration_lines.append(f"  - {family}: {advice}")
                seen_families.add(family)

        details = "\n".join(
            f"  [{family}] ({len(locs)} references)"
            for family, locs in inventory.items()
        )

        self.add_finding(
            title=f"Post-quantum cryptography migration advisory ({total_refs} references)",
            description=(
                f"Identified {total_refs} reference(s) to quantum-vulnerable "
                f"cryptographic algorithms: {algo_summary}. While these algorithms "
                "remain secure against classical computers, they are vulnerable to "
                "attacks by cryptographically relevant quantum computers (CRQCs). "
                "NIST has published post-quantum cryptography standards (FIPS 203, "
                "204, 205) and recommends beginning migration planning now."
            ),
            severity=Severity.INFO,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI07"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"Quantum-vulnerable algorithms: {algo_summary}",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Begin planning migration to NIST post-quantum cryptography standards:\n"
                + "\n".join(migration_lines) + "\n"
                "General guidance:\n"
                "  - ML-KEM (FIPS 203): replaces RSA/ECDH for key encapsulation\n"
                "  - ML-DSA (FIPS 204): replaces RSA/ECDSA/DSA for digital signatures\n"
                "  - SLH-DSA (FIPS 205): stateless hash-based signatures (conservative alternative)\n"
                "  - Implement crypto-agility to facilitate future algorithm transitions\n"
                "  - Consider hybrid modes (classical + PQC) during the transition period\n"
                "  - Prioritize long-lived secrets and data requiring long-term confidentiality"
            ),
            references=[
                "https://csrc.nist.gov/projects/post-quantum-cryptography",
                "https://csrc.nist.gov/pubs/fips/203/final",
                "https://csrc.nist.gov/pubs/fips/204/final",
                "https://csrc.nist.gov/pubs/fips/205/final",
            ],
            cvss_score=None,
            ai_risk_score=3.0,
        )

    # ------------------------------------------------------------------
    # 10. Weak PRNG Detection
    # ------------------------------------------------------------------

    async def _check_weak_prng(self) -> None:
        """Detect usage of non-cryptographic PRNGs in security-relevant Python code."""
        cid = self.context.container_id
        if not cid:
            return

        # Find Python files using the 'random' module for potential security operations
        random_usage = await self._exec_in_container(
            "grep -r -n 'import random\\|from random import' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc\\|test\\|mock' | head -30"
        )

        if not random_usage:
            return

        # Identify specific weak PRNG calls in those files
        weak_calls = await self._exec_in_container(
            "grep -r -n -E 'random\\.(random|randint|choice|randrange|sample|"
            "getrandbits|uniform|shuffle)\\s*\\(' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__\\|.pyc\\|test' | head -30"
        )

        if not weak_calls:
            return

        # Check if the same files also use secure alternatives
        secure_usage = await self._exec_in_container(
            "grep -r -l 'import secrets\\|from secrets import\\|os\\.urandom' "
            "/app /src /opt 2>/dev/null | "
            "grep -v 'node_modules\\|.git\\|__pycache__' | head -20"
        )

        # Determine which files use weak PRNG without secure alternatives
        weak_files: set[str] = set()
        for line in weak_calls.splitlines():
            if ":" in line:
                filepath = line.split(":")[0]
                weak_files.add(filepath)

        secure_files: set[str] = set()
        if secure_usage:
            for line in secure_usage.splitlines():
                secure_files.add(line.strip())

        # Files that only use weak PRNG are more concerning
        only_weak = weak_files - secure_files

        # Contextual check: search for security-sensitive usage patterns
        security_context = await self._exec_in_container(
            "grep -r -n -E 'random\\.(random|randint|choice|getrandbits)\\s*\\(' "
            "/app /src /opt 2>/dev/null | "
            "grep -i -E 'token|key|secret|nonce|salt|iv|password|session|auth|csrf' | "
            "grep -v 'test\\|mock' | head -20"
        )

        severity = Severity.HIGH if security_context else Severity.MEDIUM
        call_count = len(weak_calls.strip().splitlines())

        evidence_items = [
            Evidence(
                type="file_content",
                summary=f"Weak PRNG calls ({call_count} occurrences)",
                raw_data=weak_calls[:2000],
                location=f"container:{cid}",
            ),
        ]
        if security_context:
            evidence_items.append(
                Evidence(
                    type="file_content",
                    summary="Weak PRNG in security-sensitive context",
                    raw_data=security_context[:2000],
                    location=f"container:{cid}",
                )
            )

        self.add_finding(
            title=f"Non-cryptographic PRNG used ({call_count} occurrences"
                  f"{', ' + str(len(only_weak)) + ' files without secure alternative' if only_weak else ''})",
            description=(
                f"Found {call_count} usage(s) of Python's 'random' module, which "
                "uses the Mersenne Twister PRNG. This generator is not "
                "cryptographically secure and its output is predictable after "
                "observing 624 consecutive values. "
                + (
                    "Some of these usages appear in security-sensitive contexts "
                    "(token generation, key derivation, nonces, etc.), posing a "
                    "direct security risk."
                    if security_context else
                    "While some usages may be non-security-critical (e.g., data "
                    "shuffling for ML), any use for generating tokens, keys, IVs, "
                    "or nonces is vulnerable."
                )
            ),
            severity=severity,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MEASURE"],
            evidence=evidence_items,
            remediation=(
                "Replace 'random' module usage with cryptographically secure "
                "alternatives for all security-sensitive operations:\n"
                "  - secrets.token_bytes() / secrets.token_hex() for tokens\n"
                "  - secrets.token_urlsafe() for URL-safe tokens\n"
                "  - secrets.choice() for secure random selection\n"
                "  - os.urandom() for raw cryptographic random bytes\n"
                "The 'random' module is acceptable only for non-security purposes "
                "such as ML data augmentation or statistical sampling."
            ),
            references=[
                "https://docs.python.org/3/library/secrets.html",
            ],
            cvss_score=7.0 if security_context else 4.5,
        )
