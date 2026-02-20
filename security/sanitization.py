"""
Output Sanitization

Sanitize data received from external sources before:
1. Displaying to users
2. Passing to LLMs (see also prompt_defense.py)
3. Storing in our systems
"""

import html
import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class SanitizedString:
    """
    A string that has been sanitized.

    Wrapping in this type makes it clear in the code that
    sanitization has occurred.
    """
    value: str
    original_length: int
    was_truncated: bool
    was_modified: bool

    def __str__(self) -> str:
        return self.value


class Sanitizer:
    """
    Sanitizes data from external/untrusted sources.

    External sources include:
    - OSV.dev API responses
    - CISA KEV catalog
    - EPSS API
    - Any future scanner integrations
    - User-uploaded CSV files
    """

    # Maximum lengths for various fields
    MAX_SUMMARY_LENGTH = 500
    MAX_DETAILS_LENGTH = 5000
    MAX_REFERENCE_URL_LENGTH = 2000
    MAX_PACKAGE_NAME_LENGTH = 214

    # Patterns to strip from external text
    # These could be used for prompt injection or display issues
    STRIP_PATTERNS = [
        re.compile(r"<[^>]+>"),  # HTML tags
        re.compile(r"\x00"),  # Null bytes
        re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f]"),  # Control characters (except \t \n \r)
    ]

    # Suspicious patterns that might indicate prompt injection attempts
    SUSPICIOUS_PATTERNS = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions|ignore\s+all\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(previous|above|all)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now", re.IGNORECASE),
        re.compile(r"new\s+instructions:", re.IGNORECASE),
        re.compile(r"system\s*:", re.IGNORECASE),
        re.compile(r"<\|.*?\|>"),  # Token-like patterns
        re.compile(r"\[INST\]", re.IGNORECASE),  # Instruction markers
    ]

    @classmethod
    def sanitize_text(
        cls,
        text: Optional[str],
        max_length: int = 5000,
        field_name: str = "text",
    ) -> SanitizedString:
        """
        Sanitize a text string from an external source.

        Args:
            text: The text to sanitize
            max_length: Maximum allowed length
            field_name: Name of the field (for logging)

        Returns:
            SanitizedString with sanitized content
        """
        if text is None:
            return SanitizedString(
                value="",
                original_length=0,
                was_truncated=False,
                was_modified=False,
            )

        if not isinstance(text, str):
            text = str(text)

        original_length = len(text)
        modified = False

        # Strip dangerous patterns
        for pattern in cls.STRIP_PATTERNS:
            new_text = pattern.sub("", text)
            if new_text != text:
                modified = True
                text = new_text

        # Normalize whitespace
        text = " ".join(text.split())

        # Truncate if too long
        truncated = False
        if len(text) > max_length:
            text = text[:max_length - 3] + "..."
            truncated = True

        return SanitizedString(
            value=text,
            original_length=original_length,
            was_truncated=truncated,
            was_modified=modified or truncated,
        )

    @classmethod
    def sanitize_url(cls, url: Optional[str]) -> Optional[str]:
        """
        Sanitize a URL from an external source.

        Args:
            url: The URL to sanitize

        Returns:
            Sanitized URL or None if invalid
        """
        if not url or not isinstance(url, str):
            return None

        url = url.strip()

        # Length check
        if len(url) > cls.MAX_REFERENCE_URL_LENGTH:
            return None

        # Must start with http:// or https://
        if not url.startswith(("http://", "https://")):
            return None

        # No javascript: or data: after redirect
        if "javascript:" in url.lower() or "data:" in url.lower():
            return None

        # Basic URL character validation
        if not re.match(r"^https?://[\w\-\.]+[/\w\-\.\?=&%#]*$", url):
            # URL has unusual characters - escape them
            url = html.escape(url)

        return url

    @classmethod
    def sanitize_external_dict(
        cls,
        data: dict[str, Any],
        text_fields: Optional[list[str]] = None,
        url_fields: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Sanitize all text fields in a dictionary from an external source.

        Args:
            data: Dictionary to sanitize
            text_fields: List of field names that contain text
            url_fields: List of field names that contain URLs

        Returns:
            Sanitized dictionary (new copy)
        """
        text_fields = text_fields or ["summary", "details", "description", "notes"]
        url_fields = url_fields or ["url", "reference", "link"]

        result = {}

        for key, value in data.items():
            if key in text_fields and isinstance(value, str):
                result[key] = str(cls.sanitize_text(value))
            elif key in url_fields and isinstance(value, str):
                result[key] = cls.sanitize_url(value)
            elif isinstance(value, dict):
                result[key] = cls.sanitize_external_dict(value, text_fields, url_fields)
            elif isinstance(value, list):
                result[key] = [
                    cls.sanitize_external_dict(item, text_fields, url_fields)
                    if isinstance(item, dict)
                    else str(cls.sanitize_text(item)) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                result[key] = value

        return result

    @classmethod
    def check_for_injection_patterns(cls, text: str) -> list[str]:
        """
        Check text for patterns that might indicate prompt injection.

        This doesn't block the text, but flags it for logging/review.

        Args:
            text: Text to check

        Returns:
            List of suspicious patterns found
        """
        if not text:
            return []

        found = []
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                found.append(pattern.pattern)

        return found

    @classmethod
    def sanitize_for_display(cls, text: str) -> str:
        """
        Sanitize text for display in terminal/UI.

        Escapes any characters that could cause display issues.

        Args:
            text: Text to sanitize

        Returns:
            Display-safe text
        """
        if not text:
            return ""

        # Remove ANSI escape codes that could manipulate terminal
        text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)

        # Remove other escape sequences
        text = re.sub(r"\x1b[^[]*", "", text)

        return text
