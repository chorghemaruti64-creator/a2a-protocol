"""
Session data model for A2A Protocol.

Represents an active session between client and server.
Includes session lifecycle state and message tracking.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class SessionStatus(Enum):
    """Session lifecycle states."""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"


@dataclass
class Session:
    """
    Represents an active A2A session.
    
    Fields:
        session_id: Base64url random (unique identifier)
        client_did: Client DID (verified from handshake)
        server_did: Server DID (verified from handshake)
        manifest_hash: Hash of agreed manifest (client + server)
        created_at: Timestamp when session was created
        expires_at: Timestamp when session expires
        message_count: Number of messages exchanged (incremented per request)
        policy_hash: Hash of agreed policy document
        status: Current lifecycle status (ACTIVE, EXPIRED, CLOSED)
        last_activity: Timestamp of last activity
        session_commitment: Session commitment hash (Issue #1 - session hijacking prevention)
        policy: Full policy document (for per-request intent filtering)
        last_sequence: Last validated request sequence number (Issue #8 - replay prevention)
    """
    
    session_id: str
    client_did: str
    server_did: str
    manifest_hash: str
    policy_hash: str
    created_at: float
    expires_at: float
    message_count: int = 0
    status: SessionStatus = SessionStatus.ACTIVE
    last_activity: float = field(default_factory=time.time)
    session_commitment: Optional[str] = None  # Issue #1: Session hijacking prevention
    policy: Optional[dict] = None  # Issue #6: Intent filtering per-request
    last_sequence: int = 0  # Issue #8: Request sequence tracking
    
    def is_expired(self) -> bool:
        """
        Check if session has expired.
        
        Returns:
            True if current time >= expires_at, False otherwise
        """
        return time.time() >= self.expires_at
    
    def is_active(self) -> bool:
        """
        Check if session is active (not expired, not closed).
        
        Returns:
            True if status is ACTIVE and not expired
        """
        if self.status != SessionStatus.ACTIVE:
            return False
        if self.is_expired():
            return False
        return True
    
    def increment_message_count(self) -> int:
        """
        Increment message count and update last activity timestamp.
        
        Returns:
            New message count
        """
        self.message_count += 1
        self.last_activity = time.time()
        return self.message_count
    
    def to_dict(self) -> dict:
        """
        Serialize session to dictionary.
        
        Returns:
            Dictionary representation of session
        """
        return {
            'session_id': self.session_id,
            'client_did': self.client_did,
            'server_did': self.server_did,
            'manifest_hash': self.manifest_hash,
            'policy_hash': self.policy_hash,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'message_count': self.message_count,
            'status': self.status.value,
            'last_activity': self.last_activity,
            'session_commitment': self.session_commitment,
            'policy': self.policy,
            'last_sequence': self.last_sequence,
        }
