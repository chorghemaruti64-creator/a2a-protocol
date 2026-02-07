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
from typing import Dict, Optional
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
        
        Returns:
            Created Session object
        
        Raises:
            SessionError: If session_id already exists
        """
        with self._lock:
            if session_id in self._sessions:
                raise SessionError(f"Session already exists: {session_id}")
            
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
            )
            
            self._sessions[session_id] = session
            
            # Track client session
            if client_did not in self._client_sessions:
                self._client_sessions[client_did] = set()
            self._client_sessions[client_did].add(session_id)
            
            return session
    
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
