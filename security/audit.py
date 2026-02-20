"""
Audit Logging

Log all operations that cross trust boundaries:
- Network calls to external APIs
- File system reads/writes
- LLM API calls
- User input processing
"""

import json
import logging
import os
import sys
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class TrustBoundary(Enum):
    """Types of trust boundary crossings."""

    # Network - external API calls
    NETWORK_OSV = "network.osv"
    NETWORK_CISA_KEV = "network.cisa_kev"
    NETWORK_EPSS = "network.epss"
    NETWORK_ANTHROPIC = "network.anthropic"
    NETWORK_OTHER = "network.other"

    # File system
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"

    # User input
    USER_INPUT_CLI = "user.input.cli"
    USER_INPUT_CHAT = "user.input.chat"

    # Data processing
    EXTERNAL_DATA_PARSE = "data.external.parse"
    LLM_PROMPT_BUILD = "llm.prompt.build"


@dataclass
class AuditEvent:
    """An audit log event."""

    # Event identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    correlation_id: Optional[str] = None

    # What happened
    boundary: TrustBoundary = TrustBoundary.NETWORK_OTHER
    action: str = ""
    success: bool = True
    error: Optional[str] = None

    # Context (be careful not to log sensitive data)
    source: Optional[str] = None  # Where data came from
    destination: Optional[str] = None  # Where data went
    data_type: Optional[str] = None  # Type of data processed
    record_count: Optional[int] = None  # Number of records if applicable

    # Sanitized metadata (no secrets, no PII)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Security flags
    validation_passed: bool = True
    sanitization_applied: bool = False
    suspicious_patterns_found: list[str] = field(default_factory=list)


class AuditLogger:
    """
    Centralized audit logging for security-relevant events.

    All trust boundary crossings should be logged through this class.
    """

    _instance: Optional["AuditLogger"] = None
    _correlation_id: Optional[str] = None

    def __init__(
        self,
        log_file: Optional[Path] = None,
        log_level: int = logging.INFO,
        also_print: bool = False,
    ):
        self.log_file = log_file or Path("./data/audit.log")
        self.also_print = also_print

        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Set up logger
        self.logger = logging.getLogger("vm-agent.audit")
        self.logger.setLevel(log_level)
        self.logger.handlers = []  # Clear existing handlers

        # File handler - JSON lines format
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(file_handler)

        # Console handler if requested
        if also_print:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(
                logging.Formatter("[AUDIT] %(message)s")
            )
            self.logger.addHandler(console_handler)

    @classmethod
    def get_instance(cls) -> "AuditLogger":
        """Get or create the singleton audit logger."""
        if cls._instance is None:
            cls._instance = AuditLogger()
        return cls._instance

    @classmethod
    def set_correlation_id(cls, correlation_id: str) -> None:
        """Set correlation ID for the current request context."""
        cls._correlation_id = correlation_id

    @classmethod
    def get_correlation_id(cls) -> Optional[str]:
        """Get the current correlation ID."""
        return cls._correlation_id

    @classmethod
    @contextmanager
    def correlation_context(cls, correlation_id: Optional[str] = None):
        """Context manager for setting correlation ID."""
        old_id = cls._correlation_id
        cls._correlation_id = correlation_id or str(uuid.uuid4())
        try:
            yield cls._correlation_id
        finally:
            cls._correlation_id = old_id

    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        # Add correlation ID if available
        if self._correlation_id and not event.correlation_id:
            event.correlation_id = self._correlation_id

        # Convert to dict for JSON serialization
        event_dict = asdict(event)
        event_dict["boundary"] = event.boundary.value

        # Log as JSON line
        self.logger.info(json.dumps(event_dict, default=str))

    def log_network_call(
        self,
        boundary: TrustBoundary,
        url: str,
        method: str = "GET",
        success: bool = True,
        error: Optional[str] = None,
        response_size: Optional[int] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Log a network API call."""
        # Sanitize URL - remove any query params that might contain secrets
        safe_url = url.split("?")[0] if "?" in url else url

        event = AuditEvent(
            boundary=boundary,
            action=f"{method} {safe_url}",
            success=success,
            error=error,
            destination=safe_url,
            metadata={
                "method": method,
                "response_size": response_size,
                "duration_ms": duration_ms,
            },
        )
        self.log(event)

    def log_file_operation(
        self,
        operation: str,  # "read" or "write"
        file_path: Path,
        success: bool = True,
        error: Optional[str] = None,
        record_count: Optional[int] = None,
    ) -> None:
        """Log a file system operation."""
        boundary = TrustBoundary.FILE_READ if operation == "read" else TrustBoundary.FILE_WRITE

        event = AuditEvent(
            boundary=boundary,
            action=f"{operation} {file_path.name}",
            success=success,
            error=error,
            destination=str(file_path),
            record_count=record_count,
        )
        self.log(event)

    def log_user_input(
        self,
        input_type: str,  # "cli" or "chat"
        action: str,
        validation_passed: bool = True,
        input_length: Optional[int] = None,
    ) -> None:
        """Log user input processing."""
        boundary = (
            TrustBoundary.USER_INPUT_CLI
            if input_type == "cli"
            else TrustBoundary.USER_INPUT_CHAT
        )

        event = AuditEvent(
            boundary=boundary,
            action=action,
            validation_passed=validation_passed,
            source="user",
            metadata={"input_length": input_length},
        )
        self.log(event)

    def log_llm_call(
        self,
        model: str,
        prompt_length: int,
        response_length: Optional[int] = None,
        success: bool = True,
        error: Optional[str] = None,
        external_data_included: bool = False,
        suspicious_patterns: Optional[list[str]] = None,
    ) -> None:
        """Log an LLM API call."""
        event = AuditEvent(
            boundary=TrustBoundary.NETWORK_ANTHROPIC,
            action=f"llm.call.{model}",
            success=success,
            error=error,
            metadata={
                "model": model,
                "prompt_length": prompt_length,
                "response_length": response_length,
                "external_data_included": external_data_included,
            },
            suspicious_patterns_found=suspicious_patterns or [],
        )
        self.log(event)

    def log_external_data_parse(
        self,
        source: str,
        data_type: str,
        record_count: int,
        sanitization_applied: bool = True,
        suspicious_patterns: Optional[list[str]] = None,
    ) -> None:
        """Log parsing of external data."""
        event = AuditEvent(
            boundary=TrustBoundary.EXTERNAL_DATA_PARSE,
            action=f"parse.{data_type}",
            source=source,
            data_type=data_type,
            record_count=record_count,
            sanitization_applied=sanitization_applied,
            suspicious_patterns_found=suspicious_patterns or [],
        )
        self.log(event)


# Convenience function
def audit() -> AuditLogger:
    """Get the audit logger instance."""
    return AuditLogger.get_instance()
