"""
A2A Standard Error Codes and Exceptions.

See: /spec/A2A_PROTOCOL_v1.md#8-error-handling
"""

import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum


class ErrorCode(Enum):
    """Standard A2A error codes."""
    UNVERIFIED_AGENT = "UNVERIFIED_AGENT"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    INVALID_INTENT = "INVALID_INTENT"
    PROTOCOL_VERSION_UNSUPPORTED = "PROTOCOL_VERSION_UNSUPPORTED"
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    TIMEOUT = "TIMEOUT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass
class A2AError(Exception):
    """
    Base exception for A2A errors.

    Attributes:
        code: Standard error code
        message: Human-readable error message
        details: Additional error details (dict)
        recoverable: Whether this error is recoverable (can retry)
        request_id: Correlation ID for logging
        http_status: Recommended HTTP status code
    """

    code: str
    message: str
    details: Dict[str, Any] = None
    recoverable: bool = False
    request_id: Optional[str] = None
    http_status: int = 500

    def __post_init__(self):
        if self.details is None:
            self.details = {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "error_code": self.code,
            "error_message": self.message,
            "details": self.details,
            "request_id": self.request_id,
            "recoverable": self.recoverable,
        }


class UnverifiedAgentError(A2AError):
    """Agent identity cannot be verified."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(
            code=ErrorCode.UNVERIFIED_AGENT.value,
            message=message,
            recoverable=False,
            request_id=request_id,
            http_status=401,
        )


class InvalidManifestError(A2AError):
    """Manifest format or content invalid."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(
            code=ErrorCode.INVALID_MANIFEST.value,
            message=message,
            recoverable=False,
            request_id=request_id,
            http_status=400,
        )


class PolicyError(A2AError):
    """Policy violation (rate limit, blocked intent, etc)."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code=ErrorCode.POLICY_VIOLATION.value,
            message=message,
            details=details or {},
            recoverable=False,
            request_id=request_id,
            http_status=403,
        )


class RateLimitError(A2AError):
    """Rate limit exceeded."""

    def __init__(
        self,
        limit: int,
        period: int,
        current_rate: int,
        reset_at: int,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code=ErrorCode.RATE_LIMIT_EXCEEDED.value,
            message=f"Rate limit: {limit} requests per {period} seconds",
            details={
                "limit": limit,
                "period": period,
                "current_rate": current_rate,
                "reset_at": reset_at,
                "retry_after_seconds": reset_at - int(time.time()),
            },
            recoverable=True,
            request_id=request_id,
            http_status=429,
        )


class HandshakeError(A2AError):
    """Handshake protocol error."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(
            code=ErrorCode.HANDSHAKE_FAILED.value,
            message=message,
            recoverable=True,
            request_id=request_id,
            http_status=500,
        )


class SessionExpiredError(A2AError):
    """Session has expired."""

    def __init__(self, session_id: str, request_id: Optional[str] = None):
        super().__init__(
            code=ErrorCode.SESSION_EXPIRED.value,
            message=f"Session {session_id} has expired",
            recoverable=True,
            request_id=request_id,
            http_status=401,
        )


class TimeoutError(A2AError):
    """Operation timed out."""

    def __init__(
        self,
        operation: str,
        timeout_seconds: float,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            code=ErrorCode.TIMEOUT.value,
            message=f"{operation} timed out after {timeout_seconds}s",
            recoverable=True,
            request_id=request_id,
            http_status=504,
        )


class ServiceUnavailableError(A2AError):
    """Service temporarily unavailable."""

    def __init__(self, message: str = "Service unavailable", request_id: Optional[str] = None):
        super().__init__(
            code=ErrorCode.SERVICE_UNAVAILABLE.value,
            message=message,
            recoverable=True,
            request_id=request_id,
            http_status=503,
        )
