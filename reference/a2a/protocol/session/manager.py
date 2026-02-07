"""
Session manager for A2A Protocol.

Handles session lifecycle:
- CREATE: Create new session from handshake
- BIND: Associate session with DIDs and manifest
- VALIDATE: Verify session not expired/closed
- TRACK: Increment message count and update activity
- EXPIRE: Mark as expired when timeout reached
- TEARDOWN: Close session explicitly

Thread-safe using locks for concurrent access.
"""

import threading
import time
from typing import Dict, Optional, Any
from hashlib import sha256
from .session import Session, SessionStatus
from .errors import (
    SessionNotFoundError,
    SessionExpiredError,
    SessionClosedError,
)


class SessionManager:
    """
    Manages active sessions.
    
    Thread-safe in-memory session store keyed by session_id.
    Tracks client DID -> session_ids for concurrent session limits.
    """
    
    def __init__(self):
        """Initialize session manager."""
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()
        # Track client_did -> [session_ids] for concurrent session limits
        self._client_sessions: Dict[str, set] = {}
    
    def create_session(
        self,
        session_id: str,
        client_did: str,
        server_did: str,
        manifest_hash: str,
        policy_hash: str,
        expires_at: float,
        client_manifest_hash: Optional[str] = None,
        server_manifest_hash: Optional[str] = None,
        nonce_a: Optional[str] = None,
        nonce_b: Optional[str] = None,
        policy: Optional[Any] = None,
    ) -> Session:
        """
        Create a new session.
        
        Args:
            session_id: Unique session identifier
            client_did: Verified client DID
            server_did: Verified server DID
            manifest_hash: Hash of agreed manifest
            policy_hash: Hash of agreed policy
            expires_at: Timestamp when session expires
            client_manifest_hash: Client manifest hash (for session commitment)
            server_manifest_hash: Server manifest hash (for session commitment)
            nonce_a: Nonce A from handshake (for session commitment)
            nonce_b: Nonce B from handshake (for session commitment)
            policy: Full policy document (for intent filtering)
        
        Returns:
            Created Session object
        
        Raises:
            SessionError: If session_id already exists
        """
        with self._lock:
            if session_id in self._sessions:
                raise SessionError(f"Session already exists: {session_id}")
            
            # Compute session commitment (Issue #1: Session hijacking prevention)
            session_commitment = None
            if client_manifest_hash and server_manifest_hash and nonce_a and nonce_b:
                commitment_input = f"{client_manifest_hash}|{server_manifest_hash}|{nonce_a}|{nonce_b}"
                session_commitment = f"sha256:{sha256(commitment_input.encode()).hexdigest()}"
            
            session = Session(
                session_id=session_id,
                client_did=client_did,
                server_did=server_did,
                manifest_hash=manifest_hash,
                policy_hash=policy_hash,
                created_at=time.time(),
                expires_at=expires_at,
                message_count=0,
                status=SessionStatus.ACTIVE,
                session_commitment=session_commitment,
                policy=policy,
                last_sequence=0,
            )
            
            self._sessions[session_id] = session
            
            # Track client session
            if client_did not in self._client_sessions:
                self._client_sessions[client_did] = set()
            self._client_sessions[client_did].add(session_id)
            
            return session
    
    def validate_session_commitment(self, session_id: str, received_commitment: str) -> bool:
        """
        Validate session commitment (Issue #1: Session hijacking prevention).
        
        Args:
            session_id: Session identifier
            received_commitment: Commitment from client request
        
        Returns:
            True if commitment is valid
        
        Raises:
            SessionError: If commitment does not match
        """
        session = self.get_session(session_id)
        
        if not session.session_commitment:
            # Session created without commitment binding (backward compatible)
            return True
        
        if received_commitment != session.session_commitment:
            raise SessionError(
                "SESSION_COMMITMENT_MISMATCH",
                status_code=401,
            )
        
        return True
    
    def validate_sequence(self, session_id: str, sequence: int) -> bool:
        """
        Validate request sequence number (Issue #8: Out-of-order request prevention).
        
        Args:
            session_id: Session identifier
            sequence: Request sequence number
        
        Returns:
            True if sequence is valid
        
        Raises:
            SessionError: If sequence is out of order
        """
        session = self.get_session(session_id)
        
        if sequence <= session.last_sequence:
            raise SessionError(
                f"OUT_OF_ORDER_SEQUENCE",
                status_code=400,
            )
        
        # Atomic update of last_sequence
        with self._lock:
            if sequence > session.last_sequence:
                session.last_sequence = sequence
        
        return True
    
    def get_session(self, session_id: str) -> Session:
        """
        Get session by ID.
        
        Args:
            session_id: Session identifier
        
        Returns:
            Session object
        
        Raises:
            SessionNotFoundError: If session does not exist
        """
        with self._lock:
            if session_id not in self._sessions:
                raise SessionNotFoundError(session_id)
            return self._sessions[session_id]
    
    def validate_session(self, session_id: str) -> bool:
        """
        Validate that session is active.
        
        Checks:
        - Session exists
        - Status is ACTIVE
        - Not expired
        
        Args:
            session_id: Session identifier
        
        Returns:
            True if session is valid (active and not expired)
        
        Raises:
            SessionNotFoundError: If session does not exist
            SessionExpiredError: If session has expired
            SessionClosedError: If session is closed
        """
        session = self.get_session(session_id)
        
        # Check closure status first
        if session.status == SessionStatus.CLOSED:
            raise SessionClosedError(session_id)
        
        # Check expiry
        if session.is_expired():
            with self._lock:
                session.status = SessionStatus.EXPIRED
            raise SessionExpiredError(session_id)
        
        # Check active
        if not session.is_active():
            raise SessionExpiredError(session_id)
        
        return True
    
    def increment_message_count(self, session_id: str) -> int:
        """
        Increment message count for a session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            New message count
        
        Raises:
            SessionNotFoundError: If session does not exist
            SessionExpiredError: If session has expired
        """
        session = self.get_session(session_id)
        
        if session.is_expired():
            with self._lock:
                session.status = SessionStatus.EXPIRED
            raise SessionExpiredError(session_id)
        
        with self._lock:
            return session.increment_message_count()
    
    def close_session(self, session_id: str) -> None:
        """
        Close a session explicitly.
        
        Args:
            session_id: Session identifier
        
        Raises:
            SessionNotFoundError: If session does not exist
        """
        session = self.get_session(session_id)
        
        with self._lock:
            session.status = SessionStatus.CLOSED
            # Remove from client tracking
            client_did = session.client_did
            if client_did in self._client_sessions:
                self._client_sessions[client_did].discard(session_id)
    
    def cleanup_expired(self) -> int:
        """
        Mark all expired sessions as EXPIRED.
        
        Returns:
            Count of sessions marked as expired
        """
        expired_count = 0
        with self._lock:
            for session in self._sessions.values():
                if session.is_expired() and session.status != SessionStatus.EXPIRED:
                    session.status = SessionStatus.EXPIRED
                    expired_count += 1
        return expired_count
    
    def get_client_active_sessions(self, client_did: str) -> int:
        """
        Get count of active sessions for a client.
        
        Args:
            client_did: Client DID
        
        Returns:
            Count of active sessions
        """
        with self._lock:
            session_ids = self._client_sessions.get(client_did, set())
            count = 0
            for sid in session_ids:
                if sid in self._sessions:
                    session = self._sessions[sid]
                    if session.is_active():
                        count += 1
            return count
    
    def get_all_sessions(self) -> list:
        """
        Get all sessions (for testing/monitoring).
        
        Returns:
            List of all sessions
        """
        with self._lock:
            return list(self._sessions.values())
    
    def clear_all(self) -> None:
        """Clear all sessions (for testing)."""
        with self._lock:
            self._sessions.clear()
            self._client_sessions.clear()


# Import SessionError from errors
from .errors import SessionError
