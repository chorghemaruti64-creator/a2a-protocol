"""
Audit Log for A2A Protocol (Issue #7).

Provides tamper-proof, append-only audit logging.
Each entry is signed with HMAC-SHA256 using a secret key.
Integrity can be verified by re-computing signatures.

Thread-safe using locks for concurrent access.
"""

import json
import hmac
import hashlib
import time
from typing import List, Tuple, Optional
from dataclasses import dataclass, asdict
from threading import Lock


@dataclass
class AuditLogEntry:
    """
    Single audit log entry.
    
    Fields:
        timestamp: When this event occurred (unix timestamp)
        session_id: Session ID (if applicable)
        client_did: Client DID
        server_did: Server DID
        intent_goal: Goal of intent (e.g., "query", "action")
        status: "success" or "error"
        duration_ms: How long the request took
        error_code: Error code (if status is error)
        request_id: Request ID (if applicable)
    """
    timestamp: int
    session_id: str
    client_did: str
    server_did: str
    intent_goal: str
    status: str  # "success" or "error"
    duration_ms: int
    error_code: Optional[str] = None
    request_id: Optional[str] = None
    
    def compute_signature(self, secret_key: str) -> str:
        """
        Compute HMAC-SHA256 signature of this entry.
        
        Args:
            secret_key: Secret key for HMAC
        
        Returns:
            Hex-encoded signature
        """
        entry_dict = asdict(self)
        entry_json = json.dumps(entry_dict, sort_keys=True, separators=(',', ':'))
        sig = hmac.new(
            secret_key.encode(),
            entry_json.encode(),
            hashlib.sha256
        ).hexdigest()
        return sig


class AuditLog:
    """
    Thread-safe, append-only audit log.
    
    Each entry is signed with HMAC-SHA256.
    Tampering with entries can be detected by verifying signatures.
    """
    
    def __init__(self, secret_key: str) -> None:
        """
        Initialize audit log.
        
        Args:
            secret_key: Secret key for HMAC signing
        """
        self.secret_key = secret_key
        # List of (entry, signature) tuples
        self.entries: List[Tuple[AuditLogEntry, str]] = []
        self.lock = Lock()
    
    def log_entry(self, entry: AuditLogEntry) -> None:
        """
        Append entry with signature (append-only).
        
        Args:
            entry: Audit log entry to append
        """
        with self.lock:
            sig = entry.compute_signature(self.secret_key)
            self.entries.append((entry, sig))
    
    def verify_integrity(self) -> bool:
        """
        Verify no entries were tampered with.
        
        Returns:
            True if all signatures are valid, False otherwise
        """
        with self.lock:
            for (entry, stored_sig) in self.entries:
                expected_sig = entry.compute_signature(self.secret_key)
                if expected_sig != stored_sig:
                    return False
        return True
    
    def get_entries(self) -> List[AuditLogEntry]:
        """
        Get all audit log entries (without signatures).
        
        Returns:
            List of audit log entries
        """
        with self.lock:
            return [entry for (entry, _) in self.entries]
    
    def export_signed(self) -> str:
        """
        Export audit log with all signatures.
        
        Returns:
            JSON string with entries and signatures
        """
        with self.lock:
            return json.dumps([
                {
                    "entry": asdict(entry),
                    "signature": sig
                }
                for (entry, sig) in self.entries
            ], indent=2)
    
    def count(self) -> int:
        """
        Get count of entries.
        
        Returns:
            Number of entries
        """
        with self.lock:
            return len(self.entries)
    
    def clear_all(self) -> None:
        """Clear all entries (for testing)."""
        with self.lock:
            self.entries.clear()
