"""
Input Validation

All untrusted input must be validated before use.
This module provides validators for common input types.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(self, field: str, value: str, reason: str):
        self.field = field
        self.value = value[:100]  # Truncate for safety in logs
        self.reason = reason
        super().__init__(f"Validation failed for {field}: {reason}")


class InputValidator:
    """
    Validates and sanitizes user input.

    All user-provided input should pass through these validators
    before being used in API calls, database queries, or passed to LLMs.
    """

    # CVE ID format: CVE-YYYY-NNNNN (4+ digits after year)
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    # GHSA ID format: GHSA-xxxx-xxxx-xxxx (base32-ish)
    GHSA_PATTERN = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)

    # Canonical ecosystem names as OSV.dev expects them (case-sensitive)
    ECOSYSTEM_CANONICAL: dict[str, str] = {
        "npm": "npm",
        "pypi": "PyPI",
        "go": "Go",
        "crates.io": "crates.io",
        "maven": "Maven",
        "nuget": "NuGet",
        "packagist": "Packagist",
        "rubygems": "RubyGems",
        "hex": "Hex",
        "pub": "Pub",
        "swifturl": "SwiftURL",
        "linux": "Linux",
        "debian": "Debian",
        "alpine": "Alpine",
        "ubuntu": "Ubuntu",
        "rocky linux": "Rocky Linux",
    }

    # Package ecosystem whitelist (lowercase keys for case-insensitive lookup)
    VALID_ECOSYSTEMS = frozenset(ECOSYSTEM_CANONICAL.keys())

    # Package name: alphanumeric, hyphens, underscores, slashes, dots, @
    # Must not contain shell metacharacters or path traversal
    PACKAGE_NAME_PATTERN = re.compile(r"^[@a-zA-Z0-9][\w\-\./@]{0,213}$")

    # Version string: semver-ish, alphanumeric with dots/hyphens
    VERSION_PATTERN = re.compile(r"^[a-zA-Z0-9][\w\.\-\+]{0,127}$")

    # Dangerous patterns that should never appear in input
    DANGEROUS_PATTERNS = [
        re.compile(r"\.\./"),  # Path traversal
        re.compile(r"[;&|`$]"),  # Shell metacharacters
        re.compile(r"<script", re.IGNORECASE),  # XSS
        re.compile(r"javascript:", re.IGNORECASE),  # XSS
    ]

    @classmethod
    def validate_cve_id(cls, cve_id: str) -> str:
        """
        Validate and normalize a CVE ID.

        Args:
            cve_id: User-provided CVE identifier

        Returns:
            Normalized CVE ID (uppercase)

        Raises:
            ValidationError: If the CVE ID format is invalid
        """
        if not cve_id or not isinstance(cve_id, str):
            raise ValidationError("cve_id", str(cve_id), "CVE ID is required")

        cve_id = cve_id.strip()

        if len(cve_id) > 20:
            raise ValidationError("cve_id", cve_id, "CVE ID too long")

        if not cls.CVE_PATTERN.match(cve_id):
            raise ValidationError(
                "cve_id",
                cve_id,
                "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN"
            )

        return cve_id.upper()

    @classmethod
    def validate_vuln_id(cls, vuln_id: str) -> str:
        """
        Validate a vulnerability ID (CVE, GHSA, or OSV format).

        Args:
            vuln_id: User-provided vulnerability identifier

        Returns:
            Normalized vulnerability ID

        Raises:
            ValidationError: If the format is invalid
        """
        if not vuln_id or not isinstance(vuln_id, str):
            raise ValidationError("vuln_id", str(vuln_id), "Vulnerability ID is required")

        vuln_id = vuln_id.strip()

        if len(vuln_id) > 50:
            raise ValidationError("vuln_id", vuln_id, "Vulnerability ID too long")

        # Check for dangerous patterns
        cls._check_dangerous_patterns(vuln_id, "vuln_id")

        # Accept CVE format
        if cls.CVE_PATTERN.match(vuln_id):
            return vuln_id.upper()

        # Accept GHSA format
        if cls.GHSA_PATTERN.match(vuln_id):
            return vuln_id.upper()

        # Accept generic OSV format (alphanumeric with hyphens)
        if re.match(r"^[A-Z]{2,10}-[\w\-]{1,40}$", vuln_id, re.IGNORECASE):
            return vuln_id.upper()

        raise ValidationError(
            "vuln_id",
            vuln_id,
            "Invalid vulnerability ID format"
        )

    @classmethod
    def validate_ecosystem(cls, ecosystem: str) -> str:
        """
        Validate a package ecosystem name.

        Args:
            ecosystem: User-provided ecosystem name

        Returns:
            Normalized ecosystem name

        Raises:
            ValidationError: If the ecosystem is not recognized
        """
        if not ecosystem or not isinstance(ecosystem, str):
            raise ValidationError("ecosystem", str(ecosystem), "Ecosystem is required")

        ecosystem = ecosystem.strip().lower()

        if ecosystem not in cls.VALID_ECOSYSTEMS:
            raise ValidationError(
                "ecosystem",
                ecosystem,
                f"Unknown ecosystem. Valid options: {', '.join(sorted(cls.ECOSYSTEM_CANONICAL.values()))}"
            )

        return cls.ECOSYSTEM_CANONICAL[ecosystem]

    @classmethod
    def validate_package_name(cls, package_name: str) -> str:
        """
        Validate a package name.

        Args:
            package_name: User-provided package name

        Returns:
            Validated package name

        Raises:
            ValidationError: If the package name contains invalid characters
        """
        if not package_name or not isinstance(package_name, str):
            raise ValidationError("package_name", str(package_name), "Package name is required")

        package_name = package_name.strip()

        if len(package_name) > 214:  # npm limit
            raise ValidationError("package_name", package_name, "Package name too long")

        cls._check_dangerous_patterns(package_name, "package_name")

        if not cls.PACKAGE_NAME_PATTERN.match(package_name):
            raise ValidationError(
                "package_name",
                package_name,
                "Invalid package name. Use alphanumeric characters, hyphens, dots, and slashes only."
            )

        return package_name

    @classmethod
    def validate_version(cls, version: Optional[str]) -> Optional[str]:
        """
        Validate a version string.

        Args:
            version: User-provided version string (optional)

        Returns:
            Validated version string or None

        Raises:
            ValidationError: If the version format is invalid
        """
        if not version:
            return None

        if not isinstance(version, str):
            raise ValidationError("version", str(version), "Version must be a string")

        version = version.strip()

        if len(version) > 128:
            raise ValidationError("version", version, "Version string too long")

        cls._check_dangerous_patterns(version, "version")

        if not cls.VERSION_PATTERN.match(version):
            raise ValidationError(
                "version",
                version,
                "Invalid version format"
            )

        return version

    @classmethod
    def validate_team_name(cls, team_name: Optional[str]) -> Optional[str]:
        """
        Validate a team/recipient name.

        Args:
            team_name: User-provided team name

        Returns:
            Validated team name or None
        """
        if not team_name:
            return None

        if not isinstance(team_name, str):
            raise ValidationError("team_name", str(team_name), "Team name must be a string")

        team_name = team_name.strip()

        if len(team_name) > 100:
            raise ValidationError("team_name", team_name, "Team name too long")

        cls._check_dangerous_patterns(team_name, "team_name")

        # Allow alphanumeric, spaces, hyphens, underscores, @ for handles
        if not re.match(r"^[\w\s\-@\.]{1,100}$", team_name):
            raise ValidationError(
                "team_name",
                team_name,
                "Invalid team name characters"
            )

        return team_name

    @classmethod
    def validate_user_message(cls, message: str, max_length: int = 10000) -> str:
        """
        Validate user chat message input.

        This is for free-form text that will be sent to the LLM.
        We validate length and check for obvious issues, but prompt
        injection defense happens separately.

        Args:
            message: User-provided message
            max_length: Maximum allowed length

        Returns:
            Validated message
        """
        if not message or not isinstance(message, str):
            raise ValidationError("message", "", "Message is required")

        message = message.strip()

        if len(message) > max_length:
            raise ValidationError(
                "message",
                message[:50] + "...",
                f"Message too long (max {max_length} characters)"
            )

        if len(message) < 1:
            raise ValidationError("message", "", "Message cannot be empty")

        return message

    @classmethod
    def _check_dangerous_patterns(cls, value: str, field_name: str) -> None:
        """Check for dangerous patterns in input."""
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(value):
                raise ValidationError(
                    field_name,
                    value,
                    "Input contains potentially dangerous characters"
                )
