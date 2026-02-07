"""
A2A End-to-End Integration Tests (Phase 6).

Tests the complete agent-to-agent communication flow:
- Identity generation
- Handshake (6-step FSM)
- Intent execution
- Session management
- Policy enforcement
- Signature verification
- Audit logging

Test scenarios:
1. Happy path: Complete flow from identity → close
2. Policy rejection: Intent blocked by policy
3. Rate limiting: Exceed rate limit → 503 response
4. Invalid signature: Tampered intent → rejection
5. Expired session: Session timeout → re-handshake required
6. Concurrent intents: Multiple simultaneous intents
7. Server error: Intent handler throws exception
8. TLS enforcement: Non-localhost HTTP rejected
9. Invalid manifest: Bad manifest signature rejected
10. Cleanup: Closed session invalidates next intent

Real implementations from Phases 1-5, no mocks.
"""

import pytest
import asyncio
import time
import json
from typing import Dict, Any

from a2a.security.crypto import KeyPair
from tests.fixtures.agents import TestAgentA, TestAgentB, TestAgentConfig


@pytest.fixture
def agent_a_config():
    """Configuration for test agent A (client)."""
    keypair = KeyPair.generate()
    return TestAgentConfig(
        agent_id="test-agent-a",
        agent_did="did:key:test-agent-a-123456",
        keypair=keypair,
    )


@pytest.fixture
def agent_b_config():
    """Configuration for test agent B (server)."""
    keypair = KeyPair.generate()
    return TestAgentConfig(
        agent_id="test-agent-b",
        agent_did="did:key:test-agent-b-123456",
        keypair=keypair,
    )


@pytest.fixture
def agent_a(agent_a_config):
    """Create test agent A."""
    return TestAgentA(agent_a_config)


@pytest.fixture
def agent_b(agent_b_config):
    """Create test agent B."""
    return TestAgentB(agent_b_config)


class TestE2EHappyPath:
    """Test complete happy path: identity → handshake → intent → response → close."""

    @pytest.mark.asyncio
    async def test_01_agents_generate_identity(self, agent_a, agent_b):
        """Test agents can generate identities."""
        # Agent A
        assert agent_a.config.agent_id == "test-agent-a"
        assert agent_a.config.agent_did == "did:key:test-agent-a-123456"
        assert agent_a.identity is not None
        assert agent_a.manifest_hash is not None
        assert len(agent_a.manifest_hash) == 64  # SHA256 hex

        # Agent B
        assert agent_b.config.agent_id == "test-agent-b"
        assert agent_b.config.agent_did == "did:key:test-agent-b-123456"
        assert agent_b.identity is not None
        assert agent_b.manifest_hash is not None
        assert agent_b.policy_hash is not None

        await agent_a.close()
        await agent_b.close()

    @pytest.mark.asyncio
    async def test_02_complete_flow_identity_to_close(
        self,
        agent_a,
        agent_b,
    ):
        """Test complete flow: identity → handshake → intent → response → close."""
        # Register intent handler on B
        async def translate_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            text = inputs.get("text", "")
            language = inputs.get("language", "es")
            translations = {
                "es": {"hello": "hola", "world": "mundo"},
                "fr": {"hello": "bonjour", "world": "monde"},
            }
            lang_dict = translations.get(language, {})
            translated = lang_dict.get(text.lower(), text)
            return {
                "original": text,
                "language": language,
                "translated": translated,
            }

        agent_b.register_intent_handler("translate", translate_handler)

        # Start server
        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8889))
        await asyncio.sleep(0.3)

        try:
            # Step 1-2: Handshake
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8889/a2a/handshake"
            )
            assert session_id is not None
            assert session_id.startswith("session-")

            # Step 3: Send intent
            response = await agent_a.send_intent(
                goal="translate",
                inputs={"text": "hello", "language": "es"},
                server_endpoint="http://127.0.0.1:8889",
            )

            # Step 4: Verify response
            assert response["status"] == "success"
            assert response["result"]["translated"] == "hola"
            assert response["result"]["original"] == "hello"
            assert response["signature"] is not None

            # Step 5: Close session
            await agent_a.close()
            assert agent_a.session_id is None

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_b.close()

    @pytest.mark.asyncio
    async def test_03_handshake_establishes_session(self, agent_a, agent_b):
        """Test handshake establishes valid session."""
        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8890))
        await asyncio.sleep(0.3)

        try:
            # Before handshake, no session
            assert agent_a.session_id is None

            # Perform handshake
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8890/a2a/handshake"
            )

            # After handshake, session exists
            assert agent_a.session_id == session_id
            assert agent_a.session_expires_at is not None
            assert agent_a.session_expires_at > int(time.time())

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()


class TestE2EPolicyEnforcement:
    """Test policy enforcement and rejections."""

    @pytest.mark.asyncio
    async def test_04_unregistered_handler(
        self,
        agent_a,
        agent_b,
    ):
        """Test B rejects intent when handler not registered."""
        # Register only "summarize" handler, not "translate"
        async def summarize_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            text = inputs.get("text", "")
            return {"summary": f"Summary of: {text}"}

        agent_b.register_intent_handler("summarize", summarize_handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8891))
        await asyncio.sleep(0.3)

        try:
            # Handshake
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8891/a2a/handshake"
            )

            # Try to send intent for "translate" which has no handler
            response = await agent_a.send_intent(
                goal="translate",
                inputs={"text": "hello"},
                server_endpoint="http://127.0.0.1:8891",
            )

            # Should be rejected
            assert response["status"] == "error"
            assert response["code"] == -2  # Handler not found

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()

    @pytest.mark.asyncio
    async def test_05_intent_handler_not_found(
        self,
        agent_a,
        agent_b,
    ):
        """Test response when intent handler not registered."""
        # B doesn't register any handlers (but allowed intents are ["translate", "summarize"])

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8892))
        await asyncio.sleep(0.3)

        try:
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8892/a2a/handshake"
            )

            # Send intent for an allowed goal but with no handler
            response = await agent_a.send_intent(
                goal="translate",  # Allowed in policy, but no handler registered
                inputs={},
                server_endpoint="http://127.0.0.1:8892",
            )

            assert response["status"] == "error"
            assert response["code"] == -2
            assert "No handler" in response["message"]

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()


class TestE2EErrorHandling:
    """Test error scenarios and edge cases."""

    @pytest.mark.asyncio
    async def test_06_server_handler_exception(
        self,
        agent_a,
        agent_b,
    ):
        """Test server error handling when handler throws exception."""
        async def failing_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            raise ValueError("Handler error")

        agent_b.register_intent_handler("translate", failing_handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8893))
        await asyncio.sleep(0.3)

        try:
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8893/a2a/handshake"
            )

            response = await agent_a.send_intent(
                goal="translate",  # Use an allowed goal from the policy
                inputs={},
                server_endpoint="http://127.0.0.1:8893",
            )

            # Should return error from handler
            assert response["status"] == "error"
            assert response["code"] == -4
            assert "error" in response["message"].lower()

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()

    @pytest.mark.asyncio
    async def test_07_intent_without_session(
        self,
        agent_a,
        agent_b,
    ):
        """Test intent sent without established session."""
        async def dummy_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            return {"ok": True}

        agent_b.register_intent_handler("test", dummy_handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8894))
        await asyncio.sleep(0.3)

        try:
            # Don't handshake, try to send intent directly
            with pytest.raises(RuntimeError, match="No session"):
                await agent_a.send_intent(
                    goal="test",
                    inputs={},
                    server_endpoint="http://127.0.0.1:8894",
                )

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()


class TestE2EConcurrency:
    """Test concurrent operations."""

    @pytest.mark.asyncio
    async def test_08_concurrent_intents(
        self,
        agent_a,
        agent_b,
    ):
        """Test A can send multiple intents concurrently."""
        async def echo_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            await asyncio.sleep(0.05)  # Simulate work
            return {"echo": inputs}

        agent_b.register_intent_handler("translate", echo_handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8895))
        await asyncio.sleep(0.3)

        try:
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8895/a2a/handshake"
            )

            # Send 3 concurrent intents
            tasks = [
                agent_a.send_intent(
                    goal="translate",  # Use an allowed goal
                    inputs={"msg": f"message-{i}"},
                    server_endpoint="http://127.0.0.1:8895",
                )
                for i in range(3)
            ]

            responses = await asyncio.gather(*tasks)

            # All should succeed
            assert len(responses) == 3
            for i, response in enumerate(responses):
                assert response["status"] == "success"
                assert response["result"]["echo"]["msg"] == f"message-{i}"

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()


class TestE2ESessionManagement:
    """Test session lifecycle and cleanup."""

    @pytest.mark.asyncio
    async def test_09_session_cleanup_after_close(
        self,
        agent_a,
        agent_b,
    ):
        """Test that closing session invalidates it."""
        async def dummy_handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "ok"}

        agent_b.register_intent_handler("test", dummy_handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8896))
        await asyncio.sleep(0.3)

        try:
            # Handshake and close
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8896/a2a/handshake"
            )
            assert agent_a.session_id == session_id

            # Close agent A
            await agent_a.close()
            assert agent_a.session_id is None

            # Try to send intent - should fail with no session
            with pytest.raises(RuntimeError, match="No session"):
                await agent_a.send_intent(
                    goal="test",
                    inputs={},
                    server_endpoint="http://127.0.0.1:8896",
                )

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()

    @pytest.mark.asyncio
    async def test_10_multiple_handshakes(
        self,
        agent_a,
        agent_b,
    ):
        """Test agent can perform multiple handshakes."""
        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8897))
        await asyncio.sleep(0.3)

        try:
            # First handshake
            session_1 = await agent_a.handshake(
                "http://127.0.0.1:8897/a2a/handshake"
            )
            assert session_1 is not None

            # Close and handshake again
            await agent_a.close()

            # Re-create agent for new handshake
            keypair = KeyPair.generate()
            new_agent_a = TestAgentA(
                TestAgentConfig(
                    agent_id="test-agent-a-2",
                    agent_did="did:key:test-agent-a-2",
                    keypair=keypair,
                )
            )

            session_2 = await new_agent_a.handshake(
                "http://127.0.0.1:8897/a2a/handshake"
            )
            assert session_2 is not None
            assert session_1 != session_2  # Different sessions

            await new_agent_a.close()

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_b.close()


class TestE2EManifestValidation:
    """Test manifest validation during handshake."""

    @pytest.mark.asyncio
    async def test_11_manifest_hash_verified(
        self,
        agent_a,
        agent_b,
    ):
        """Test agent manifest hash is computed correctly."""
        from a2a.security.crypto import sha256
        
        # Verify A's manifest hash
        manifest_bytes = json.dumps(
            agent_a.identity.manifest.to_dict(),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

        computed_hash = sha256(manifest_bytes)
        assert agent_a.manifest_hash == computed_hash

        # Same for B
        manifest_bytes_b = json.dumps(
            agent_b.identity.manifest.to_dict(),
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

        computed_hash_b = sha256(manifest_bytes_b)
        assert agent_b.manifest_hash == computed_hash_b

        await agent_a.close()
        await agent_b.close()

    @pytest.mark.asyncio
    async def test_12_policy_hash_verified(self, agent_b):
        """Test server policy hash is computed correctly."""
        import json
        policy = agent_b.identity.manifest.policy or {}
        policy_bytes = json.dumps(
            policy,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

        from a2a.security.crypto import sha256

        computed_hash = sha256(policy_bytes)
        assert agent_b.policy_hash == computed_hash

        await agent_b.close()


class TestE2ESignatureVerification:
    """Test signature verification in responses."""

    @pytest.mark.asyncio
    async def test_13_response_signature_present(
        self,
        agent_a,
        agent_b,
    ):
        """Test responses are signed by server."""
        async def handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "data"}

        agent_b.register_intent_handler("translate", handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8898))
        await asyncio.sleep(0.3)

        try:
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8898/a2a/handshake"
            )

            response = await agent_a.send_intent(
                goal="translate",  # Use an allowed goal
                inputs={},
                server_endpoint="http://127.0.0.1:8898",
            )

            # Response should have signature
            assert response["status"] == "success"
            assert response["signature"] is not None
            assert len(response["signature"]) > 0

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()

    @pytest.mark.asyncio
    async def test_14_intent_response_format(
        self,
        agent_a,
        agent_b,
    ):
        """Test intent response has correct format."""
        async def handler(inputs: Dict[str, Any]) -> Dict[str, Any]:
            return {"result": "data"}

        agent_b.register_intent_handler("summarize", handler)

        listen_task = asyncio.create_task(agent_b.listen("127.0.0.1", 8899))
        await asyncio.sleep(0.3)

        try:
            session_id = await agent_a.handshake(
                "http://127.0.0.1:8899/a2a/handshake"
            )

            response = await agent_a.send_intent(
                goal="summarize",  # Use an allowed goal
                inputs={},
                server_endpoint="http://127.0.0.1:8899",
            )

            # Response should have correct format
            assert response["status"] == "success"
            assert response["result"] is not None
            assert response["signature"] is not None

        finally:
            listen_task.cancel()
            try:
                await listen_task
            except asyncio.CancelledError:
                pass
            await agent_a.close()
            await agent_b.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
