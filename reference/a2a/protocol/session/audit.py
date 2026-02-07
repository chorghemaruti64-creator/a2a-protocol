"""
Audit logging for A2A Protocol sessions.

Logs all intent requests, responses, and errors.
Supports data retention policies (standard, extended, none).
In-memory storage for Phase 5 (file-based in future phases).
"""

import time
import threading
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any
from enum import Enum


class AuditStatus(Enum):
    """Status of audit log entry."""
    REQUEST = "REQUEST"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


@dataclass
class AuditLogEntry:
    """
    Single audit log entry.
    
    Fields:
        timestamp: When the request was made
        session_id: Session identifier
        client_did: Client DID
        server_did: Server DID
        intent_goal: The intent goal
        status: REQUEST, SUCCESS, or FAILURE
        duration_ms: Time taken to process (0 for REQUEST)
        error_code: HTTP status code (null for SUCCESS)
        error_message: Error message (null for SUCCESS)
    """
    timestamp: float
    session_id: str
    client_did: str
    server_did: str
    intent_goal: str
    status: str  # REQUEST, SUCCESS, FAILURE
    duration_ms: int = 0
    error_code: int = None
    error_message: str = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class AuditLog:
    """
    In-memory audit log for session activity.
    
    Tracks:
    - Intent requests (entry, exit)
    - Success/failure outcomes
    - Request duration and error details
    - Client activity for compliance
    
    Thread-safe for concurrent access.
    """
    
    def __init__(self, max_entries: int = 10000):
        """
        Initialize audit log.
        
        Args:
            max_entries: Maximum entries to keep in memory
        """
        self._entries: List[AuditLogEntry] = []
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._request_times: Dict[str, float] = {}  # session_id -> start_time
    
    def log_request(
        self,
        session_id: str,
        client_did: str,
        server_did: str,
        intent_goal: str,
    ) -> None:
        """
        Log incoming request.
        
        Args:
            session_id: Session identifier
            client_did: Client DID
            server_did: Server DID
            intent_goal: Intent goal
        """
        now = time.time()
        self._request_times[session_id] = now
        
        entry = AuditLogEntry(
            timestamp=now,
            session_id=session_id,
            client_did=client_did,
            server_did=server_did,
            intent_goal=intent_goal,
            status=AuditStatus.REQUEST.value,
        )
        
        self._add_entry(entry)
    
    def log_response(
        self,
        session_id: str,
        client_did: str,
        server_did: str,
        intent_goal: str,
    ) -> None:
        """
        Log successful response.
        
        Args:
            session_id: Session identifier
            client_did: Client DID
            server_did: Server DID
            intent_goal: Intent goal
        """
        now = time.time()
        duration_ms = 0
        if session_id in self._request_times:
            start = self._request_times[session_id]
            duration_ms = int((now - start) * 1000)
            del self._request_times[session_id]
        
        entry = AuditLogEntry(
            timestamp=now,
            session_id=session_id,
            client_did=client_did,
            server_did=server_did,
            intent_goal=intent_goal,
            status=AuditStatus.SUCCESS.value,
            duration_ms=duration_ms,
        )
        
        self._add_entry(entry)
    
    def log_error(
        self,
        session_id: str,
        client_did: str,
        server_did: str,
        intent_goal: str,
        error_code: int,
        error_message: str = "",
    ) -> None:
        """
        Log failed request.
        
        Args:
            session_id: Session identifier
            client_did: Client DID
            server_did: Server DID
            intent_goal: Intent goal
            error_code: HTTP status code
            error_message: Error description
        """
        now = time.time()
        duration_ms = 0
        if session_id in self._request_times:
            start = self._request_times[session_id]
            duration_ms = int((now - start) * 1000)
            del self._request_times[session_id]
        
        entry = AuditLogEntry(
            timestamp=now,
            session_id=session_id,
            client_did=client_did,
            server_did=server_did,
            intent_goal=intent_goal,
            status=AuditStatus.FAILURE.value,
            duration_ms=duration_ms,
            error_code=error_code,
            error_message=error_message,
        )
        
        self._add_entry(entry)
    
    def _add_entry(self, entry: AuditLogEntry) -> None:
        """
        Add entry to log with thread safety.
        
        Args:
            entry: AuditLogEntry to add
        """
        with self._lock:
            self._entries.append(entry)
            # Enforce max size by removing oldest entries
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries:]
    
    def get_logs(self, session_id: str = None, limit: int = None) -> List[dict]:
        """
        Get audit log entries.
        
        Args:
            session_id: Optional filter by session ID
            limit: Optional limit on number of entries
        
        Returns:
            List of log entries as dictionaries
        """
        with self._lock:
            entries = self._entries
            
            if session_id:
                entries = [e for e in entries if e.session_id == session_id]
            
            if limit:
                entries = entries[-limit:]
            
            return [e.to_dict() for e in entries]
    
    def get_session_logs(self, session_id: str) -> List[dict]:
        """
        Get all logs for a specific session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            List of log entries for the session
        """
        return self.get_logs(session_id=session_id)
    
    def cleanup_by_retention(self, retention_days: int) -> int:
        """
        Remove logs older than retention period.
        
        Args:
            retention_days: Keep logs younger than this
        
        Returns:
            Count of entries removed
        """
        now = time.time()
        cutoff = now - (retention_days * 86400)
        
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.timestamp > cutoff]
            after = len(self._entries)
            return before - after
    
    def count_entries(self) -> int:
        """Get total number of log entries."""
        with self._lock:
            return len(self._entries)
    
    def clear_all(self) -> None:
        """Clear all log entries (for testing)."""
        with self._lock:
            self._entries.clear()
            self._request_times.clear()
