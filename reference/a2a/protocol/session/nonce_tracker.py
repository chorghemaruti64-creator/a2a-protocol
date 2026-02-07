"""
Nonce Tracker for A2A Protocol (Issue #2).

Prevents nonce replay attacks by tracking nonces per DID.
Nonces are blacklisted for a configurable window (default 1 hour).

Thread-safe using locks for concurrent access.
"""

import time
from typing import Set, Tuple, Optional
from threading import Lock


class NonceTracker:
    """
    Track nonces per DID to prevent replay across sessions.
    
    Each DID maintains a set of (nonce, expiry_time) tuples.
    When a nonce is received, it's checked against the blacklist.
    Expired nonces are cleaned up automatically.
    """
    
    def __init__(self, blacklist_window_seconds: int = 3600) -> None:
        """
        Initialize nonce tracker.
        
        Args:
            blacklist_window_seconds: How long to remember nonces (default 1 hour)
        """
        self.blacklist_window = blacklist_window_seconds
        # {did: {(nonce, expiry_time)}}
        self.nonce_blacklist: dict[str, Set[Tuple[str, float]]] = {}
        self.lock = Lock()
    
    def add_nonce(self, did: str, nonce: str) -> None:
        """
        Track nonce as used for a DID.
        
        Args:
            did: DID that received the nonce
            nonce: Nonce value to track
        """
        with self.lock:
            if did not in self.nonce_blacklist:
                self.nonce_blacklist[did] = set()
            
            expiry_time = time.time() + self.blacklist_window
            self.nonce_blacklist[did].add((nonce, expiry_time))
    
    def is_nonce_replayed(self, did: str, nonce: str) -> bool:
        """
        Check if nonce was already used and not yet expired.
        
        Args:
            did: DID to check
            nonce: Nonce to check
        
        Returns:
            True if nonce was used within blacklist window, False otherwise
        """
        with self.lock:
            self.cleanup_expired(did)
            
            if did not in self.nonce_blacklist:
                return False
            
            now = time.time()
            for (stored_nonce, expiry_time) in self.nonce_blacklist[did]:
                if stored_nonce == nonce and expiry_time > now:
                    return True
        
        return False
    
    def cleanup_expired(self, did: str) -> None:
        """
        Remove expired nonces for a DID (called with lock held).
        
        Args:
            did: DID to clean up
        """
        if did in self.nonce_blacklist:
            now = time.time()
            self.nonce_blacklist[did] = {
                (n, exp) for (n, exp) in self.nonce_blacklist[did] if exp > now
            }
            if not self.nonce_blacklist[did]:
                del self.nonce_blacklist[did]
    
    def cleanup_all_expired(self) -> int:
        """
        Clean up all expired nonces across all DIDs.
        
        Returns:
            Count of DIDs cleaned up
        """
        with self.lock:
            cleaned_count = 0
            dids_to_cleanup = list(self.nonce_blacklist.keys())
            
            for did in dids_to_cleanup:
                self.cleanup_expired(did)
                if did not in self.nonce_blacklist:
                    cleaned_count += 1
            
            return cleaned_count
    
    def clear_all(self) -> None:
        """Clear all nonces (for testing)."""
        with self.lock:
            self.nonce_blacklist.clear()
