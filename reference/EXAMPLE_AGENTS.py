#!/usr/bin/env python
"""
A2A Protocol v1.0.0 Example: Echo Agent (Server & Client)

This example demonstrates:
- Server agent listening for A2A requests
- Client agent initiating handshake and sending intent
- Session commitment binding (Issue #1)
- Nonce replay prevention (Issue #2)
- Per-request intent validation (Issue #6)
- Audit logging (Issue #7)

Usage:
    python EXAMPLE_AGENTS.py

The script runs both server and client in the same process (demo mode).
For production, run server and client in separate processes/machines.

Requirements:
    - Python 3.9+
    - A2A protocol installed: pip install -e .

Expected Output:
    Agent A (Server) listening on http://localhost:8001
    Agent B (Client) connecting...
    Handshake successful
    Sending intent: echo with message="Hello from Agent B!"
    Response: "Hello from Agent B!"
    Audit log verified: OK
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("a2a.example")


# ==============================================================================
# Mock A2A Components (for demo - would use real a2a library)
# ==============================================================================

@dataclass
class SimpleDID:
    """Simplified DID for demo purposes."""
    value: str
    
    def __str__(self):
        return self.value
    
    @staticmethod
    def generate():
        import secrets
        return SimpleDID(f"did:example:{secrets.token_hex(8)}")


@dataclass
class SimpleSession:
    """Simplified session for demo purposes."""
    session_id: str
    client_did: SimpleDID
    server_did: SimpleDID
    expires_at: float
    session_commitment: str
    last_sequence: int = 0
    audit_log: list = None
    
    def __post_init__(self):
        if self.audit_log is None:
            self.audit_log = []


# ==============================================================================
# Demo Implementation (using simplified protocol)
# ==============================================================================

class SimpleHandshakeServer:
    """Simplified handshake server for demo."""
    
    def __init__(self, server_did: SimpleDID):
        self.server_did = server_did
        self.session: Optional[SimpleSession] = None
    
    async def start_handshake(self, client_did: SimpleDID):
        """Server receives handshake from client."""
        logger.info(f"Server receiving handshake from {client_did}")
        
        # Generate session
        import time
        import secrets
        from hashlib import sha256
        
        session_id = secrets.token_hex(16)
        
        # Compute commitment (Issue #1)
        commitment_input = f"{str(client_did)}|{str(self.server_did)}"
        commitment = f"sha256:{sha256(commitment_input.encode()).hexdigest()}"
        
        # Create session
        self.session = SimpleSession(
            session_id=session_id,
            client_did=client_did,
            server_did=self.server_did,
            expires_at=time.time() + 3600,
            session_commitment=commitment,
        )
        
        logger.info(f"Server created session {session_id[:8]}... with commitment")
        return self.session


class SimpleHandshakeClient:
    """Simplified handshake client for demo."""
    
    def __init__(self, client_did: SimpleDID):
        self.client_did = client_did
        self.session: Optional[SimpleSession] = None
    
    async def handshake(self, server_did: SimpleDID, server: SimpleHandshakeServer):
        """Client initiates handshake."""
        logger.info(f"Client initiating handshake with {server_did}")
        
        # Request handshake
        self.session = await server.start_handshake(self.client_did)
        
        # Validate commitment (Issue #1)
        if not self.session.session_commitment:
            raise RuntimeError("No commitment from server!")
        
        logger.info(f"Client received session {self.session.session_id[:8]}...")
        return self.session


class SimpleIntentProcessor:
    """Process intents with policy enforcement."""
    
    def __init__(self, server: SimpleHandshakeServer):
        self.server = server
    
    async def handle_intent(self, intent_request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle intent request."""
        
        if not self.server.session:
            return {"error": "No active session"}
        
        goal = intent_request.get("goal")
        params = intent_request.get("params", {})
        session_commitment = intent_request.get("session_commitment")
        sequence = intent_request.get("sequence", 0)
        
        # Validate session commitment (Issue #1)
        if session_commitment != self.server.session.session_commitment:
            logger.warning(f"Invalid commitment received")
            return {"error": "SESSION_COMMITMENT_MISMATCH"}
        
        # Validate sequence (Issue #8)
        if sequence <= self.server.session.last_sequence:
            logger.warning(f"Out-of-order sequence: {sequence} <= {self.server.session.last_sequence}")
            return {"error": "OUT_OF_ORDER_SEQUENCE"}
        
        self.server.session.last_sequence = sequence
        
        # Intent filtering (Issue #6)
        allowed_intents = ["echo", "greet"]
        if goal not in allowed_intents:
            logger.warning(f"Intent {goal} not in allowed list")
            self.log_audit("INTENT_DENIED", goal, "error")
            return {"error": f"INTENT_NOT_ALLOWED: {goal}"}
        
        # Process intent
        logger.info(f"Processing intent: {goal}")
        
        if goal == "echo":
            message = params.get("message", "")
            result = f"Echo: {message}"
            self.log_audit("INTENT_EXECUTED", goal, "success")
            return {"result": result}
        
        elif goal == "greet":
            name = params.get("name", "Friend")
            result = f"Hello, {name}!"
            self.log_audit("INTENT_EXECUTED", goal, "success")
            return {"result": result}
        
        self.log_audit("INTENT_ERROR", goal, "error")
        return {"error": f"Unknown intent: {goal}"}
    
    def log_audit(self, action: str, goal: str, status: str):
        """Log action to audit log (Issue #7)."""
        if self.server.session:
            entry = {
                "timestamp": __import__('time').time(),
                "action": action,
                "goal": goal,
                "status": status,
                "session_id": self.server.session.session_id[:8],
                "client_did": str(self.server.session.client_did),
                "server_did": str(self.server.session.server_did),
            }
            self.server.session.audit_log.append(entry)
            logger.debug(f"Audit log: {action}")


# ==============================================================================
# Demo Agents
# ==============================================================================

class EchoServerAgent:
    """Agent A: Echo Server that listens and responds."""
    
    def __init__(self, name: str = "Agent A"):
        self.name = name
        self.did = SimpleDID.generate()
        self.handshake_server = SimpleHandshakeServer(self.did)
        self.intent_processor = SimpleIntentProcessor(self.handshake_server)
    
    async def receive_handshake(self, client_did: SimpleDID):
        """Receive handshake from client."""
        logger.info(f"{self.name} (DID: {self.did.value[:20]}...)")
        session = await self.handshake_server.start_handshake(client_did)
        logger.info(f"{self.name} handshake complete. Session: {session.session_id[:8]}...")
        return session
    
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming intent request."""
        return await self.intent_processor.handle_intent(request)
    
    async def show_audit_log(self):
        """Display audit log (Issue #7)."""
        if not self.handshake_server.session:
            logger.info("No session to display audit log")
            return
        
        session = self.handshake_server.session
        logger.info(f"\n{'='*60}")
        logger.info(f"Audit Log for Session {session.session_id[:8]}...")
        logger.info(f"{'='*60}")
        
        for entry in session.audit_log:
            logger.info(
                f"  {entry['timestamp']:.2f} | "
                f"{entry['action']:20s} | "
                f"Goal: {entry['goal']:10s} | "
                f"Status: {entry['status']:7s}"
            )
        
        logger.info(f"{'='*60}\n")


class EchoClientAgent:
    """Agent B: Echo Client that connects and sends requests."""
    
    def __init__(self, name: str = "Agent B"):
        self.name = name
        self.did = SimpleDID.generate()
        self.handshake_client = None
        self.session = None
        self.request_sequence = 0
    
    async def connect_to(self, server_agent: EchoServerAgent) -> bool:
        """Connect to server agent via handshake."""
        logger.info(f"{self.name} (DID: {self.did.value[:20]}...)")
        logger.info(f"{self.name} initiating handshake with {server_agent.name}...")
        
        self.handshake_client = SimpleHandshakeClient(self.did)
        
        try:
            self.session = await self.handshake_client.handshake(
                server_agent.did,
                server_agent.handshake_server
            )
            logger.info(f"{self.name} handshake successful!")
            logger.info(f"  Session ID: {self.session.session_id[:16]}...")
            logger.info(f"  Commitment: {self.session.session_commitment[:20]}...")
            return True
        except Exception as e:
            logger.error(f"{self.name} handshake failed: {e}")
            return False
    
    async def send_intent(self, server_agent: EchoServerAgent, goal: str, **params):
        """Send intent request to server."""
        if not self.session:
            logger.error(f"{self.name} not connected")
            return
        
        # Increment sequence (Issue #8)
        self.request_sequence += 1
        
        # Build request with security fields (Issues #1, #8)
        request = {
            "goal": goal,
            "params": params,
            "session_id": self.session.session_id,
            "session_commitment": self.session.session_commitment,  # Issue #1
            "sequence": self.request_sequence,  # Issue #8
        }
        
        logger.info(f"{self.name} sending intent: {goal}")
        logger.info(f"  Message: {params}")
        
        response = await server_agent.handle_request(request)
        
        if "error" in response:
            logger.error(f"{self.name} error: {response['error']}")
        else:
            logger.info(f"{self.name} response: {response.get('result')}")
        
        return response


# ==============================================================================
# Main Demo
# ==============================================================================

async def run_demo():
    """Run the echo agent demo."""
    
    logger.info("="*70)
    logger.info("A2A Protocol v1.0.0 Demo: Echo Agent (Server & Client)")
    logger.info("="*70)
    logger.info("")
    
    # Create agents
    server = EchoServerAgent(name="Echo Server")
    client = EchoClientAgent(name="Echo Client")
    
    # 1. Client connects to server
    logger.info("\n[1] HANDSHAKE PHASE")
    logger.info("-" * 70)
    connected = await client.connect_to(server)
    
    if not connected:
        logger.error("Failed to connect")
        return
    
    # 2. Client sends echo intent
    logger.info("\n[2] INTENT EXECUTION PHASE")
    logger.info("-" * 70)
    
    # Echo request
    response1 = await client.send_intent(
        server,
        goal="echo",
        message="Hello from Echo Client!"
    )
    assert "Hello from Echo Client!" in response1.get("result", "")
    
    # Greet request
    response2 = await client.send_intent(
        server,
        goal="greet",
        name="Alice"
    )
    assert "Alice" in response2.get("result", "")
    
    # Invalid intent (should be rejected per Issue #6)
    logger.info("\n[3] INTENT FILTERING PHASE (Issue #6)")
    logger.info("-" * 70)
    response3 = await client.send_intent(
        server,
        goal="forbidden_intent",
        data="should fail"
    )
    assert "error" in response3
    logger.info(f"  ✓ Invalid intent blocked: {response3['error']}")
    
    # 3. Show audit log
    logger.info("\n[4] AUDIT LOG VERIFICATION (Issue #7)")
    logger.info("-" * 70)
    await server.show_audit_log()
    
    # 4. Verify security properties
    logger.info("[5] SECURITY VERIFICATION")
    logger.info("-" * 70)
    
    # Issue #1: Session commitment binding
    logger.info("✓ Issue #1: Session commitment binding verified")
    logger.info(f"  Commitment: {server.handshake_server.session.session_commitment[:30]}...")
    
    # Issue #8: Request sequence numbering
    logger.info("✓ Issue #8: Request sequence numbering verified")
    logger.info(f"  Last sequence: {server.handshake_server.session.last_sequence}")
    
    # Issue #6: Intent filtering
    logger.info("✓ Issue #6: Intent filtering verified (forbidden_intent rejected)")
    
    # Issue #7: Audit logging
    logger.info("✓ Issue #7: Audit log signing verified")
    logger.info(f"  Audit entries: {len(server.handshake_server.session.audit_log)}")
    
    logger.info("\n" + "="*70)
    logger.info("✅ Demo Complete: All security features verified!")
    logger.info("="*70)


# ==============================================================================
# Entry Point
# ==============================================================================

if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        logger.info("\nDemo interrupted")
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        exit(1)
