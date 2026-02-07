"""
Policy enforcement for A2A Protocol sessions.

Enforces per-session policies:
- Rate limiting (requests per period)
- Intent filtering (allow/deny lists)
- Payload size limits
- Concurrent session limits
- Data retention

Returns (allowed: bool, reason: str, status_code: int) tuples.
"""

import time
from typing import Tuple, Optional, List, Dict, Any
from dataclasses import dataclass, field
from .session import Session
from .manager import SessionManager
from .errors import (
    RateLimitExceededError,
    IntentNotAllowedError,
    PayloadTooLargeError,
    TooManyConcurrentSessionsError,
    PolicyEnforcementError,
)


@dataclass
class RateLimitPolicy:
    """Rate limiting configuration."""
    requests_per_second: int = 10
    requests_per_minute: int = 600
    requests_per_hour: int = 36000


@dataclass
class IntentPolicy:
    """Intent filtering configuration."""
    allowed_intents: List[str] = field(default_factory=list)  # Whitelist
    blocked_intents: List[str] = field(default_factory=list)  # Blacklist


@dataclass
class PayloadPolicy:
    """Payload size configuration."""
    max_payload_bytes: int = 1_000_000  # 1 MB default


@dataclass
class ConcurrencyPolicy:
    """Concurrent session configuration."""
    max_concurrent_sessions: int = 10


@dataclass
class DataRetentionPolicy:
    """Data retention configuration."""
    retention_mode: str = "standard"  # standard, extended, none
    log_retention_days: int = 30


@dataclass
class SessionPolicy:
    """Complete policy for a session."""
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    intent: IntentPolicy = field(default_factory=IntentPolicy)
    payload: PayloadPolicy = field(default_factory=PayloadPolicy)
    concurrency: ConcurrencyPolicy = field(default_factory=ConcurrencyPolicy)
    data_retention: DataRetentionPolicy = field(default_factory=DataRetentionPolicy)


class PolicyEnforcer:
    """
    Enforces policies on session requests.
    
    Tracks rate limit state per session using message timestamps.
    Chains multiple policy checks: rate_limit -> intent -> payload -> concurrent.
    """
    
    def __init__(self, session_manager: SessionManager):
        """
        Initialize policy enforcer.
        
        Args:
            session_manager: SessionManager instance for session lookups
        """
        self.session_manager = session_manager
        # Track request times per session for rate limiting
        self._request_times: Dict[str, List[float]] = {}
    
    def check_rate_limit(
        self,
        session: Session,
        policy: SessionPolicy,
    ) -> bool:
        """
        Check if session is within rate limits.
        
        Enforces per-second, per-minute, and per-hour limits.
        
        Args:
            session: Session object
            policy: SessionPolicy with rate_limit config
        
        Returns:
            True if within limits
        
        Raises:
            RateLimitExceededError: If any limit exceeded
        """
        now = time.time()
        session_id = session.session_id
        
        if session_id not in self._request_times:
            self._request_times[session_id] = []
        
        times = self._request_times[session_id]
        
        # Remove old requests outside windows
        one_hour_ago = now - 3600
        times[:] = [t for t in times if t > one_hour_ago]
        
        # Check per-second limit
        second_ago = now - 1
        requests_per_sec = sum(1 for t in times if t > second_ago)
        if requests_per_sec >= policy.rate_limit.requests_per_second:
            raise RateLimitExceededError(
                policy.rate_limit.requests_per_second,
                "per second"
            )
        
        # Check per-minute limit
        minute_ago = now - 60
        requests_per_min = sum(1 for t in times if t > minute_ago)
        if requests_per_min >= policy.rate_limit.requests_per_minute:
            raise RateLimitExceededError(
                policy.rate_limit.requests_per_minute,
                "per minute"
            )
        
        # Check per-hour limit
        requests_per_hr = len(times)
        if requests_per_hr >= policy.rate_limit.requests_per_hour:
            raise RateLimitExceededError(
                policy.rate_limit.requests_per_hour,
                "per hour"
            )
        
        # Record this request
        times.append(now)
        return True
    
    def check_intent_allowed(
        self,
        intent_goal: str,
        policy: SessionPolicy,
    ) -> bool:
        """
        Check if intent is allowed by policy.
        
        Logic:
        - If intent in blocked_intents: REJECT
        - Else if allowed_intents is empty: ALLOW
        - Else if intent in allowed_intents: ALLOW
        - Else: REJECT
        
        Args:
            intent_goal: The intent goal string
            policy: SessionPolicy with intent config
        
        Returns:
            True if intent is allowed
        
        Raises:
            IntentNotAllowedError: If intent is blocked or not in whitelist
        """
        # Check blacklist first
        if intent_goal in policy.intent.blocked_intents:
            raise IntentNotAllowedError(
                intent_goal,
                reason="in blocked list"
            )
        
        # If whitelist exists, check it
        if policy.intent.allowed_intents:
            if intent_goal not in policy.intent.allowed_intents:
                raise IntentNotAllowedError(
                    intent_goal,
                    reason="not in allowed list"
                )
        
        return True
    
    def check_payload_size(
        self,
        payload: bytes,
        policy: SessionPolicy,
    ) -> bool:
        """
        Check if payload is within size limits.
        
        Args:
            payload: The request payload
            policy: SessionPolicy with payload config
        
        Returns:
            True if payload is within limits
        
        Raises:
            PayloadTooLargeError: If payload exceeds max size
        """
        size = len(payload)
        if size > policy.payload.max_payload_bytes:
            raise PayloadTooLargeError(size, policy.payload.max_payload_bytes)
        return True
    
    def check_concurrent_sessions(
        self,
        client_did: str,
        policy: SessionPolicy,
    ) -> bool:
        """
        Check if client is within concurrent session limits.
        
        Args:
            client_did: Client DID
            policy: SessionPolicy with concurrency config
        
        Returns:
            True if within concurrent limits
        
        Raises:
            TooManyConcurrentSessionsError: If limit exceeded
        """
        active_count = self.session_manager.get_client_active_sessions(client_did)
        if active_count >= policy.concurrency.max_concurrent_sessions:
            raise TooManyConcurrentSessionsError(
                client_did,
                policy.concurrency.max_concurrent_sessions
            )
        return True
    
    def enforce(
        self,
        session: Session,
        policy: SessionPolicy,
        intent_goal: str,
        payload: bytes,
    ) -> Tuple[bool, str, int]:
        """
        Enforce all policy checks in sequence.
        
        Checks (in order):
        1. Rate limit
        2. Intent allowed
        3. Payload size
        4. Concurrent sessions
        
        Args:
            session: Session object
            policy: SessionPolicy to enforce
            intent_goal: Intent goal string
            payload: Request payload
        
        Returns:
            Tuple of (allowed: bool, reason: str, status_code: int)
            On success: (True, "allowed", 200)
            On failure: (False, error_message, error_status_code)
        """
        try:
            self.check_rate_limit(session, policy)
            self.check_intent_allowed(intent_goal, policy)
            self.check_payload_size(payload, policy)
            self.check_concurrent_sessions(session.client_did, policy)
            return (True, "allowed", 200)
        except RateLimitExceededError as e:
            return (False, e.message, e.status_code)
        except IntentNotAllowedError as e:
            return (False, e.message, e.status_code)
        except PayloadTooLargeError as e:
            return (False, e.message, e.status_code)
        except TooManyConcurrentSessionsError as e:
            return (False, e.message, e.status_code)
        except PolicyEnforcementError as e:
            return (False, e.message, e.status_code)
        except Exception as e:
            return (False, str(e), 500)
    
    def clear_request_history(self, session_id: str) -> None:
        """
        Clear rate limit history for a session (for testing).
        
        Args:
            session_id: Session identifier
        """
        if session_id in self._request_times:
            del self._request_times[session_id]
    
    def clear_all(self) -> None:
        """Clear all rate limit history (for testing)."""
        self._request_times.clear()
