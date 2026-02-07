"""Common types used throughout A2A."""

from dataclasses import dataclass
from typing import Optional
import uuid

@dataclass
class SessionID:
    """Unique session identifier."""
    value: str
    
    @staticmethod
    def generate() -> "SessionID":
        return SessionID(str(uuid.uuid4()))

@dataclass
class RequestID:
    """Correlation ID for a request."""
    value: str
    
    @staticmethod
    def generate() -> "RequestID":
        return RequestID(str(uuid.uuid4()))

@dataclass
class Nonce:
    """Cryptographically random nonce."""
    value: str
    
    @staticmethod
    def generate(length: int = 32) -> "Nonce":
        import secrets
        return Nonce(secrets.token_urlsafe(length))
