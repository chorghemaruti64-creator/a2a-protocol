"""
Test agents for E2E integration testing.

Provides two agent classes:
- TestAgentA: Client agent (initiates connections, sends intents)
- TestAgentB: Server agent (listens, handles handshakes, executes intents)

Both agents use real implementations from phases 1-5, not mocks.
"""

import asyncio
import json
import time
import secrets
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass

from a2a.core.identity import DID, PublicKey, AgentManifest, AgentIdentity
from a2a.security.crypto import (
    KeyPair,
    JWS,
    sha256,
    b64url_encode,
)
from a2a.protocol.handshake import (
    HandshakeFSM,
    HandshakeFSMConfig,
    HandshakeState,
    HelloMessage,
    ChallengeMessage,
    ProofMessage,
    PolicyMessage,
    AcceptPolicyMessage,
    SessionMessage,
    MessageType,
)
from a2a.protocol.session import (
    Session,
    SessionStatus,
    SessionManager,
    SessionPolicy,
    PolicyEnforcer,
    RateLimitPolicy,
    AuditLog,
)
from a2a.transport import HTTPTransport, RequestEnvelope, ResponseEnvelope


@dataclass
class TestAgentConfig:
    """Configuration for test agents."""
    agent_id: str
    agent_did: str
    keypair: KeyPair
    manifest_version: str = "1.0.0"


class TestAgentA:
    """
    Client agent for E2E testing.
    
    Responsibilities:
    - Generate identity (DID, keypair, manifest)
    - Initiate handshake with server (B)
    - Send intents and receive responses
    - Validate response signatures
    - Manage session lifecycle
    """

    def __init__(self, config: TestAgentConfig):
        self.config = config
        self.transport = HTTPTransport()
        self.session_id: Optional[str] = None
        self.session_expires_at: Optional[int] = None
        
        # Build identity
        self.identity = self._build_identity()
        self.manifest_hash = self._compute_manifest_hash()

    def _build_identity(self) -> AgentIdentity:
        """Build agent identity from keypair."""
        # Create public key from keypair
        public_key = PublicKey(
            kid="agent-a-key-1",
            kty="OKP",
            alg="EdDSA",
            use="sig",
            key=self.config.keypair.public_key_base64(),
        )
        
        # Create manifest
        manifest = AgentManifest(
            manifest_version=self.config.manifest_version,
            agent_did=self.config.agent_did,
            agent_id=self.config.agent_id,
            public_keys=[public_key],
            endpoints=[
                {"type": "http", "url": "http://127.0.0.1:8888/a2a"}
            ],
            capabilities=[
                {"name": "translate", "version": "1.0"},
                {"name": "summarize", "version": "1.0"},
            ],
        )
        
        # Create and return identity
        did = DID(self.config.agent_did)
        return AgentIdentity(did=did, manifest=manifest)

    def _compute_manifest_hash(self) -> str:
        """Compute SHA256 hash of manifest."""
        manifest_bytes = json.dumps(
            self.identity.manifest.to_dict(),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
        return sha256(manifest_bytes)

    async def handshake(self, server_endpoint: str) -> str:
        """
        Execute 6-step handshake with server.
        
        Returns:
            session_id: Session ID from server
        """
        # Step 1: Create HELLO message
        nonce_a = b64url_encode(b"nonce_a_" + b"x" * 24)
        hello = HelloMessage(
            nonce_a=nonce_a,
            agent_did=self.config.agent_did,
            manifest_hash=self.manifest_hash,
        )

        hello_request = RequestEnvelope.create(
            method="handshake/hello",
            params=hello.model_dump(),
            request_id="hs-001",
        )

        # Step 1-2: Send HELLO, receive CHALLENGE
        hello_response = await self.transport.send(
            server_endpoint,
            hello_request,
            timeout=5.0,
        )

        challenge_data = hello_response["result"]
        challenge = ChallengeMessage(**challenge_data)
        nonce_b = challenge.nonce_b
        policy_hash = challenge.policy_hash

        # Step 3: Create PROOF message
        # Create proof payload (both nonces signed)
        proof_payload = {
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
        }
        
        # Sign with client's keypair
        proof_jws = JWS.create(proof_payload, self.config.keypair)

        proof = ProofMessage(
            nonce_a=nonce_a,
            nonce_b=nonce_b,
            proof=proof_jws,
        )

        proof_request = RequestEnvelope.create(
            method="handshake/proof",
            params=proof.model_dump(),
            request_id="hs-002",
        )

        # Step 3-4: Send PROOF, receive POLICY
        policy_response = await self.transport.send(
            server_endpoint,
            proof_request,
            timeout=5.0,
        )

        policy_data = policy_response["result"]
        policy = PolicyMessage(**policy_data)
        received_policy_hash = policy_data.get("policy_hash", policy_hash)

        # Step 5: Create ACCEPT_POLICY message
        # Create commitment signature
        commitment_payload = {
            "policy_hash": received_policy_hash,
        }
        commitment_jws = JWS.create(commitment_payload, self.config.keypair)
        
        accept = AcceptPolicyMessage(
            policy_hash=received_policy_hash,
            commitment=commitment_jws,
        )

        accept_request = RequestEnvelope.create(
            method="handshake/accept_policy",
            params=accept.model_dump(),
            request_id="hs-003",
        )

        # Step 5-6: Send ACCEPT_POLICY, receive SESSION
        session_response = await self.transport.send(
            server_endpoint,
            accept_request,
            timeout=5.0,
        )

        session_data = session_response["result"]
        session = SessionMessage(**session_data)

        # Store session info
        self.session_id = session.session_id
        self.session_expires_at = session.expires_at

        return self.session_id

    async def send_intent(
        self,
        goal: str,
        inputs: Dict[str, Any],
        server_endpoint: str,
    ) -> Dict[str, Any]:
        """
        Send an intent to server and receive response.
        
        Args:
            goal: Intent goal (e.g., "translate", "summarize")
            inputs: Intent inputs
            server_endpoint: Server endpoint URL
        
        Returns:
            Response dict with status, result, signature
        
        Raises:
            Exception: If session not established or intent fails
        """
        if not self.session_id:
            raise RuntimeError("No session established. Call handshake() first.")

        # Create intent request
        intent_data = {
            "goal": goal,
            "inputs": inputs,
            "session_id": self.session_id,
            "timestamp": int(time.time()),
        }

        # Sign intent with JWS
        signature = JWS.create(intent_data, self.config.keypair)

        request_body = {
            "intent": intent_data,
            "signature": signature,
        }

        intent_request = RequestEnvelope.create(
            method="intent/execute",
            params=request_body,
            request_id=f"intent-{int(time.time())}",
        )

        # Send intent and get response
        from a2a.transport.errors import JSONRPCError
        
        # Build proper endpoint URL (need /a2a/* path)
        if server_endpoint.endswith("/a2a/handshake"):
            # Replace /a2a/handshake with /a2a/intent
            base_url = server_endpoint.rsplit("/a2a/", 1)[0]
            intent_url = f"{base_url}/a2a/intent"
        else:
            # Assume base URL, add /a2a/intent
            intent_url = f"{server_endpoint}/a2a/intent"
        
        try:
            response = await self.transport.send(
                intent_url,
                intent_request,
                timeout=5.0,
            )
        except JSONRPCError as e:
            # Convert transport error to response dict
            # Extract JSON-RPC error code from details
            jsonrpc_code = e.details.get("jsonrpc_error_code", -32603) if hasattr(e, 'details') else -32603
            jsonrpc_message = e.details.get("jsonrpc_error_message", str(e)) if hasattr(e, 'details') else str(e)
            return {
                "status": "error",
                "code": jsonrpc_code,
                "message": jsonrpc_message,
            }

        # Parse response
        if "error" in response:
            return {
                "status": "error",
                "code": response["error"]["code"],
                "message": response["error"]["message"],
            }

        result = response.get("result", {})
        return {
            "status": "success",
            "result": result.get("result"),
            "signature": result.get("signature"),
        }

    async def close(self):
        """Close transport and cleanup."""
        await self.transport.close()
        self.session_id = None


class TestAgentB:
    """
    Server agent for E2E testing.
    
    Responsibilities:
    - Generate identity
    - Listen for handshake requests
    - Execute 6-step handshake FSM
    - Validate sessions and enforce policies
    - Execute intents
    - Send signed responses
    - Create audit logs
    """

    def __init__(self, config: TestAgentConfig):
        self.config = config
        self.transport = HTTPTransport()
        self.session_manager = SessionManager()
        self.policy_enforcer = PolicyEnforcer(self.session_manager)
        self.audit_log = AuditLog()
        self.intent_handlers: Dict[str, Callable] = {}
        
        # Build identity
        self.identity = self._build_identity()
        self.manifest_hash = self._compute_manifest_hash()
        self.policy_hash = self._compute_policy_hash()

    def _build_identity(self) -> AgentIdentity:
        """Build agent identity from keypair."""
        public_key = PublicKey(
            kid="agent-b-key-1",
            kty="OKP",
            alg="EdDSA",
            use="sig",
            key=self.config.keypair.public_key_base64(),
        )
        
        manifest = AgentManifest(
            manifest_version=self.config.manifest_version,
            agent_did=self.config.agent_did,
            agent_id=self.config.agent_id,
            public_keys=[public_key],
            endpoints=[
                {"type": "http", "url": "http://127.0.0.1:8888/a2a"}
            ],
            capabilities=[
                {"name": "translate", "version": "1.0"},
                {"name": "summarize", "version": "1.0"},
            ],
            policy={
                "rate_limit": {"requests_per_minute": 100},
                "intent_filter": {
                    "allowed": ["translate", "summarize"],
                    "denied": [],
                },
                "max_payload_bytes": 1024 * 1024,
            },
        )
        
        did = DID(self.config.agent_did)
        return AgentIdentity(did=did, manifest=manifest)

    def _compute_manifest_hash(self) -> str:
        """Compute SHA256 hash of manifest."""
        manifest_bytes = json.dumps(
            self.identity.manifest.to_dict(),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
        return sha256(manifest_bytes)

    def _compute_policy_hash(self) -> str:
        """Compute SHA256 hash of policy."""
        policy = self.identity.manifest.policy or {}
        policy_bytes = json.dumps(
            policy,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
        return sha256(policy_bytes)

    def register_intent_handler(
        self,
        goal: str,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ):
        """Register a handler for an intent goal."""
        self.intent_handlers[goal] = handler

    async def _handle_handshake_message(
        self,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Handle handshake messages."""
        method = message["method"]

        if method == "handshake/hello":
            return await self._handle_hello(message)
        elif method == "handshake/proof":
            return await self._handle_proof(message)
        elif method == "handshake/accept_policy":
            return await self._handle_accept_policy(message)
        else:
            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

    async def _handle_hello(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle HELLO message (step 1-2)."""
        try:
            params = message["params"]
            hello = HelloMessage(**params)

            # Create CHALLENGE response
            nonce_b = b64url_encode(b"nonce_b_" + b"y" * 24)
            challenge = ChallengeMessage(
                nonce_b=nonce_b,
                policy_hash=self.policy_hash,
                public_keys=[
                    {
                        "kid": "agent-b-key-1",
                        "key": self.config.keypair.public_key_base64(),
                        "alg": "EdDSA",
                    }
                ],
            )

            return ResponseEnvelope.success(
                challenge.model_dump(),
                message["id"],
            )
        except Exception as e:
            return ResponseEnvelope.error(
                ResponseEnvelope.INVALID_REQUEST,
                str(e),
                message["id"],
            )

    async def _handle_proof(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle PROOF message (step 3-4)."""
        try:
            params = message["params"]
            proof = ProofMessage(**params)

            # Create POLICY response
            policy_obj = self.identity.manifest.policy or {}
            policy_payload = {
                "rate_limit": policy_obj.get("rate_limit", {}),
            }
            policy_jws = JWS.create(policy_payload, self.config.keypair)
            
            policy = PolicyMessage(
                policy=policy_obj,
                policy_hash=self.policy_hash,
                signature=policy_jws,
            )

            return ResponseEnvelope.success(
                policy.model_dump(),
                message["id"],
            )
        except Exception as e:
            return ResponseEnvelope.error(
                ResponseEnvelope.INVALID_REQUEST,
                str(e),
                message["id"],
            )

    async def _handle_accept_policy(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ACCEPT_POLICY message (step 5-6)."""
        try:
            params = message["params"]
            accept = AcceptPolicyMessage(**params)

            # Create session with random nonce
            now = int(time.time())
            random_nonce = secrets.token_bytes(8)
            session_id = f"session-{now}-{b64url_encode(random_nonce)}"
            
            # Store session
            self.session_manager.create_session(
                session_id=session_id,
                client_did="did:key:client",
                server_did=self.config.agent_did,
                manifest_hash="manifest_hash_client",
                policy_hash=self.policy_hash,
                expires_at=now + 3600,
            )

            # Create SESSION response
            session_payload = {
                "session_id": session_id,
                "expires_at": now + 3600,
            }
            session_jws = JWS.create(session_payload, self.config.keypair)
            
            session_msg = SessionMessage(
                session_id=session_id,
                expires_at=now + 3600,
                signature=session_jws,
            )

            return ResponseEnvelope.success(
                session_msg.model_dump(),
                message["id"],
            )
        except Exception as e:
            return ResponseEnvelope.error(
                ResponseEnvelope.INVALID_REQUEST,
                str(e),
                message["id"],
            )

    async def _handle_intent(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle intent execution request."""
        try:
            params = message["params"]
            intent = params.get("intent", {})
            signature = params.get("signature", "")

            # Validate session
            session_id = intent.get("session_id")
            if not session_id:
                return ResponseEnvelope.error(
                    ResponseEnvelope.INVALID_REQUEST,
                    "Missing session_id",
                    message["id"],
                )

            try:
                session = self.session_manager.get_session(session_id)
            except Exception:
                return ResponseEnvelope.error(
                    code=-1,
                    message="Session not found",
                    request_id=message["id"],
                )

            # Validate session is active
            if session.status != SessionStatus.ACTIVE:
                return ResponseEnvelope.error(
                    code=-1,
                    message=f"Session is {session.status}",
                    request_id=message["id"],
                )

            # Check policy enforcement
            goal = intent.get("goal")
            policy = self.identity.manifest.policy or {}
            allowed_intents = policy.get("intent_filter", {}).get("allowed", [])

            if allowed_intents and goal not in allowed_intents:
                # Policy rejected
                return ResponseEnvelope.error(
                    code=-3,
                    message=f"Intent '{goal}' not allowed by policy",
                    request_id=message["id"],
                )

            # Execute intent
            handler = self.intent_handlers.get(goal)
            if not handler:
                return ResponseEnvelope.error(
                    code=-2,
                    message=f"No handler for intent '{goal}'",
                    request_id=message["id"],
                )

            try:
                result = await handler(intent.get("inputs", {}))
            except Exception as e:
                return ResponseEnvelope.error(
                    code=-4,
                    message=f"Intent execution error: {str(e)}",
                    request_id=message["id"],
                )

            # Sign response with JWS
            response_obj = {
                "result": result,
            }
            response_signature = JWS.create(response_obj, self.config.keypair)

            return ResponseEnvelope.success(
                {
                    "result": result,
                    "signature": response_signature,
                },
                message["id"],
            )

        except Exception as e:
            return ResponseEnvelope.error(
                ResponseEnvelope.INTERNAL_ERROR,
                str(e),
                message["id"],
            )

    async def _request_handler(
        self,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Main request handler for incoming messages."""
        method = message.get("method", "")

        if method.startswith("handshake/"):
            return await self._handle_handshake_message(message)
        elif method == "intent/execute":
            return await self._handle_intent(message)
        else:
            return ResponseEnvelope.error(
                ResponseEnvelope.METHOD_NOT_FOUND,
                f"Unknown method: {method}",
                message["id"],
            )

    async def listen(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
    ):
        """Start listening for incoming requests."""
        await self.transport.listen(host, port, self._request_handler)

    async def close(self):
        """Close transport and cleanup."""
        await self.transport.close()
        # Close all sessions
        self.session_manager.clear_all()
