"""
Session-specific error types for A2A Protocol.

Includes standard session errors and policy enforcement errors
with appropriate HTTP status codes.
"""


class SessionError(Exception):
    """Base exception for all session-related errors."""
    
    def __init__(self, message: str, status_code: int = 500):
        """
        Initialize session error.
        
        Args:
            message: Error description
            status_code: HTTP status code to return
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class SessionNotFoundError(SessionError):
    """Session does not exist."""
    
    def __init__(self, session_id: str):
        """
        Initialize error.
        
        Args:
            session_id: The requested session ID
        """
        message = f"Session not found: {session_id}"
        super().__init__(message, status_code=404)


class SessionExpiredError(SessionError):
    """Session has expired."""
    
    def __init__(self, session_id: str):
        """
        Initialize error.
        
        Args:
            session_id: The expired session ID
        """
        message = f"Session expired: {session_id}"
        super().__init__(message, status_code=401)


class SessionClosedError(SessionError):
    """Session is closed."""
    
    def __init__(self, session_id: str):
        """
        Initialize error.
        
        Args:
            session_id: The closed session ID
        """
        message = f"Session closed: {session_id}"
        super().__init__(message, status_code=401)


class RateLimitExceededError(SessionError):
    """Rate limit has been exceeded."""
    
    def __init__(self, limit: int, period: str):
        """
        Initialize error.
        
        Args:
            limit: The exceeded rate limit
            period: The time period (e.g., "per minute", "per hour")
        """
        message = f"Rate limit exceeded: {limit} {period}"
        super().__init__(message, status_code=503)


class IntentNotAllowedError(SessionError):
    """Intent is not allowed by policy."""
    
    def __init__(self, intent_goal: str, reason: str = ""):
        """
        Initialize error.
        
        Args:
            intent_goal: The disallowed intent goal
            reason: Optional explanation
        """
        message = f"Intent not allowed: {intent_goal}"
        if reason:
            message += f" ({reason})"
        super().__init__(message, status_code=403)


class PayloadTooLargeError(SessionError):
    """Payload exceeds maximum size."""
    
    def __init__(self, size: int, max_size: int):
        """
        Initialize error.
        
        Args:
            size: Actual payload size
            max_size: Maximum allowed payload size
        """
        message = f"Payload too large: {size} > {max_size} bytes"
        super().__init__(message, status_code=400)


class TooManyConcurrentSessionsError(SessionError):
    """Too many concurrent sessions for client."""
    
    def __init__(self, client_did: str, limit: int):
        """
        Initialize error.
        
        Args:
            client_did: The client DID
            limit: The concurrent session limit
        """
        message = f"Too many concurrent sessions for {client_did}: limit {limit}"
        super().__init__(message, status_code=503)


class PolicyEnforcementError(SessionError):
    """Generic policy enforcement error."""
    
    def __init__(self, message: str, status_code: int = 403):
        """
        Initialize error.
        
        Args:
            message: Error description
            status_code: HTTP status code
        """
        super().__init__(message, status_code=status_code)
