"""
A2A Transport Layer Abstract Interface.

Defines the Transport ABC that all transport implementations must follow.
This allows for pluggable transports: HTTP, gRPC, WebSocket, etc.

Design:
- Async-first (all operations are async/await)
- Request/response envelope: JSON-RPC 2.0 standard
- Error handling: TransportError and subclasses
- Type-safe with full type hints
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Callable, Optional, Awaitable
import uuid


class Transport(ABC):
    """
    Abstract Transport Layer for A2A Protocol.

    All A2A communication flows through this interface. Implementations
    must handle JSON-RPC 2.0 message envelopes, error mapping, and
    protocol-level concerns (timeouts, retries, etc).

    Design principles:
    1. Async-first: All I/O is non-blocking
    2. Envelope-aware: Know about JSON-RPC structure
    3. Error-explicit: Raise TransportError, never silent failures
    4. Policy-neutral: Leave business logic to layers above
    5. TLS-enforced: HTTPS for production, HTTP only for testing
    """

    @abstractmethod
    async def send(
        self,
        endpoint: str,
        message: Dict[str, Any],
        timeout: float = 30.0,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a JSON-RPC request and wait for response.

        The message must be a valid JSON-RPC 2.0 request envelope:
        {
            "jsonrpc": "2.0",
            "method": "method_name",
            "params": {...},
            "id": "request_id"
        }

        Args:
            endpoint: Full URL to send to (e.g., https://host:port/a2a/handshake)
            message: JSON-RPC 2.0 request envelope as dict
            timeout: Request timeout in seconds (default 30s)
            request_id: Correlation ID for logging (auto-generated if not provided)

        Returns:
            JSON-RPC 2.0 response envelope as dict:
            {
                "jsonrpc": "2.0",
                "result": {...},  # or "error": {...}
                "id": "request_id"
            }

        Raises:
            ConnectionError: Failed to establish connection
            TimeoutError: Request exceeded timeout
            InvalidMessageError: Message format invalid
            HTTPError: HTTP-level error (400, 401, 403, 500, 503, etc)
            JSONRPCError: Server returned JSON-RPC error object
            TransportError: Other transport failures

        Note:
            - request_id is auto-generated if not provided
            - All errors include request_id for correlation
            - Timeout applies to entire request/response cycle
        """
        raise NotImplementedError

    @abstractmethod
    async def listen(
        self,
        host: str,
        port: int,
        handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
        request_id_header: str = "X-Request-ID",
    ) -> None:
        """
        Start listening for incoming requests.

        Starts an async HTTP server on the specified host/port.
        For each incoming POST request to /a2a/*, parses JSON-RPC message,
        calls handler, and returns response envelope.

        Handler signature:
            async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
                # message is JSON-RPC 2.0 request (already parsed)
                # return JSON-RPC 2.0 response or error
                return {"jsonrpc": "2.0", "result": {...}, "id": msg["id"]}

        Args:
            host: Bind address (e.g., "127.0.0.1", "0.0.0.0")
            port: Bind port (e.g., 5000)
            handler: Async function that processes incoming messages
            request_id_header: HTTP header to extract request_id from

        Behavior:
            - Listens on http://host:port/a2a/* (wildcard paths)
            - Validates JSON-RPC 2.0 envelope on all requests
            - Extracts request_id from header or message.id
            - Maps handler exceptions to HTTP status codes:
              * TransportError → appropriate status (400, 401, 403, 500, 503)
              * Other exceptions → 500 with error object
            - Returns JSON-RPC error envelope on handler exceptions
            - Supports concurrent requests (async)
            - Returns HTTP status codes per spec:
              * 200 OK for successful response
              * 400 Bad Request for invalid JSON-RPC
              * 401 Unauthorized for auth failures
              * 403 Forbidden for policy violations
              * 500 Internal Server Error for handler exceptions
              * 503 Service Unavailable for rate limiting

        Raises:
            ConnectionError: Failed to bind to port
            TransportError: Other startup failures

        Note:
            - This is a blocking call; typically run in separate task
            - Call close() to stop listening
        """
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        """
        Close transport and clean up resources.

        Closes any open connections, stops listening server, etc.
        Safe to call multiple times.

        Raises:
            TransportError: If cleanup fails
        """
        raise NotImplementedError

    @staticmethod
    def generate_request_id() -> str:
        """Generate a unique request ID (UUID)."""
        return str(uuid.uuid4())

    @staticmethod
    def validate_jsonrpc_request(message: Dict[str, Any]) -> None:
        """
        Validate JSON-RPC 2.0 request envelope.

        Args:
            message: Message dict to validate

        Raises:
            InvalidMessageError: If message is not valid JSON-RPC 2.0 request
        """
        from a2a.transport.errors import InvalidMessageError

        if not isinstance(message, dict):
            raise InvalidMessageError("Message must be a JSON object")

        if message.get("jsonrpc") != "2.0":
            raise InvalidMessageError('Missing or invalid "jsonrpc": must be "2.0"')

        if not message.get("method"):
            raise InvalidMessageError("Missing required field: method")

        if "params" not in message or not isinstance(message.get("params"), dict):
            raise InvalidMessageError("Missing or invalid field: params (must be object)")

        if not message.get("id"):
            raise InvalidMessageError("Missing required field: id")

    @staticmethod
    def validate_jsonrpc_response(message: Dict[str, Any]) -> None:
        """
        Validate JSON-RPC 2.0 response envelope.

        Args:
            message: Message dict to validate

        Raises:
            InvalidMessageError: If message is not valid JSON-RPC 2.0 response
        """
        from a2a.transport.errors import InvalidMessageError

        if not isinstance(message, dict):
            raise InvalidMessageError("Response must be a JSON object")

        if message.get("jsonrpc") != "2.0":
            raise InvalidMessageError('Missing or invalid "jsonrpc": must be "2.0"')

        if not message.get("id"):
            raise InvalidMessageError("Missing required field: id")

        # Must have either result or error, but not both
        has_result = "result" in message
        has_error = "error" in message

        if not (has_result ^ has_error):  # XOR: exactly one must be true
            raise InvalidMessageError("Response must have either 'result' or 'error', not both or neither")

        # If error, must have code and message
        if has_error:
            error = message.get("error")
            if not isinstance(error, dict):
                raise InvalidMessageError("error must be an object")
            if "code" not in error or not isinstance(error["code"], int):
                raise InvalidMessageError("error.code must be an integer")
            if "message" not in error or not isinstance(error["message"], str):
                raise InvalidMessageError("error.message must be a string")


class RequestEnvelope:
    """Helper to construct JSON-RPC 2.0 request envelopes."""

    @staticmethod
    def create(
        method: str,
        params: Dict[str, Any],
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        session_commitment: Optional[str] = None,
        sequence: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Create a JSON-RPC 2.0 request envelope.

        Args:
            method: RPC method name
            params: Method parameters (dict)
            request_id: Request ID (auto-generated if not provided)
            session_id: Session ID (optional, for session-bound requests)
            session_commitment: Session commitment hash (optional, Issue #1)
            sequence: Request sequence number (optional, Issue #8)

        Returns:
            Valid JSON-RPC 2.0 request dict
        """
        if request_id is None:
            request_id = Transport.generate_request_id()

        envelope = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id,
        }
        
        # Add session fields if provided
        if session_id is not None:
            envelope["session_id"] = session_id
        
        if session_commitment is not None:
            envelope["session_commitment"] = session_commitment
        
        if sequence is not None:
            envelope["sequence"] = sequence
        
        return envelope


class ResponseEnvelope:
    """Helper to construct JSON-RPC 2.0 response envelopes."""

    @staticmethod
    def success(
        result: Dict[str, Any],
        request_id: str,
    ) -> Dict[str, Any]:
        """
        Create a successful JSON-RPC 2.0 response.

        Args:
            result: Response result object
            request_id: Echo of request id

        Returns:
            Valid JSON-RPC 2.0 response dict
        """
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id,
        }

    @staticmethod
    def error(
        code: int,
        message: str,
        request_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a JSON-RPC 2.0 error response.

        Args:
            code: JSON-RPC error code (standard codes: -32700 to -32600)
            message: Error message string
            request_id: Echo of request id
            data: Additional error data (optional)

        Returns:
            Valid JSON-RPC 2.0 error response dict
        """
        error_obj = {
            "code": code,
            "message": message,
        }
        if data is not None:
            error_obj["data"] = data

        return {
            "jsonrpc": "2.0",
            "error": error_obj,
            "id": request_id,
        }

    # Standard JSON-RPC error codes (per spec)
    # Note: -32768 to -32000 are reserved
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    SERVER_ERROR_START = -32099
    SERVER_ERROR_END = -32000
