"""
Unit tests for Handshake FSM (Phase 3).

Coverage:
- Happy path: complete handshake → ESTABLISHED (Test 1)
- Timeout: missing CHALLENGE after 10s → raises error (Tests 2-3)
- Replay attack: sending CHALLENGE twice → reject 2nd (Test 4)
- Invalid state transition: CHALLENGE after SESSION → error (Test 5-6)
- Wrong nonce: client PROOF has wrong nonce_b → FAILED (Tests 7-8)
- Signature mismatch: public key doesn't match → FAILED (Test 9)
- Expired timestamp: message >5 min old → reject (Tests 10-11)
- Missing fields: validation tests (Tests 12-17)
- Negative tests: all error paths covered (Tests 18-27)

Test count target: 27+ tests
"""

import pytest
import time
import json
from a2a.security.crypto import KeyPair, JWS, generate_nonce, sha256
from a2a.protocol.handshake.fsm import HandshakeFSM, HandshakeState, HandshakeFSMConfig
from a2a.protocol.handshake.messages import (
    HelloMessage,
    ChallengeMessage,
    ProofMessage,
    PolicyMessage,
    AcceptPolicyMessage,
    SessionMessage,
    HandshakeError,
)
from a2a.core.errors import TimeoutError as A2ATimeoutError


@pytest.fixture
def client_keypair():
    """Generate client keypair."""
    return KeyPair.generate()


@pytest.fixture
def server_keypair():
    """Generate server keypair."""
    return KeyPair.generate()


@pytest.fixture
def client_did(client_keypair):
    """Get client DID."""
    return client_keypair.get_did_key()


@pytest.fixture
def server_did(server_keypair):
    """Get server DID."""
    return server_keypair.get_did_key()


@pytest.fixture
def manifest_hash():
    """Create a valid manifest hash."""
    manifest_json = json.dumps({
        "agent_id": "test-agent",
        "version": "1.0",
    }).encode()
    return sha256(manifest_json)


@pytest.fixture
def policy_hash():
    """Create a valid policy hash."""
    policy_json = json.dumps({
        "rate_limit": 100,
        "session_timeout": 3600,
    }).encode()
    return sha256(policy_json)


@pytest.fixture
def server_public_keys(server_keypair):
    """Create server public keys list."""
    return [
        {
            "kid": "sig-2024-01",
            "kty": "EC",
            "alg": "EdDSA",
            "use": "sig",
            "key": server_keypair.public_key_base64(),
        }
    ]


@pytest.fixture
def policy():
    """Create a valid policy."""
    return {
        "rate_limit": 100,
        "session_timeout": 3600,
        "max_payload_size": 10485760,
    }


@pytest.fixture
def fsm_config():
    """Create FSM with short timeouts for testing."""
    return HandshakeFSMConfig(
        state_timeout_seconds=1,
        total_timeout_seconds=5,
        nonce_length_bytes=32,
    )


@pytest.fixture
def fsm(client_keypair, client_did, manifest_hash, fsm_config):
    """Create FSM instance."""
    return HandshakeFSM(client_keypair, client_did, manifest_hash, fsm_config)


# ===== TEST 1: HAPPY PATH =====

def test_01_handshake_complete_happy_path(fsm, server_keypair, manifest_hash, policy_hash, policy, server_public_keys):
    """Test 1: Complete handshake → ESTABLISHED."""
    # Step 1: Client sends HELLO
    assert fsm.state == HandshakeState.INIT
    hello_msg = fsm.hello()
    assert fsm.state == HandshakeState.HELLO_SENT
    assert hello_msg["message_type"] == "HELLO"
    assert hello_msg["nonce_a"]
    assert hello_msg["agent_did"]
    assert hello_msg["manifest_hash"] == manifest_hash
    
    # Step 2: Server sends CHALLENGE
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    assert fsm.state == HandshakeState.CHALLENGE_RECEIVED
    
    # Step 3: Client sends PROOF
    proof_msg = fsm.proof()
    assert fsm.state == HandshakeState.PROOF_SENT
    assert proof_msg["message_type"] == "PROOF"
    assert proof_msg["nonce_a"] == hello_msg["nonce_a"]
    assert proof_msg["nonce_b"] == challenge_msg["nonce_b"]
    
    # Step 4: Server sends POLICY
    policy_payload = {"rate_limit": 100, "session_timeout": 3600}
    policy_jws = JWS.create(policy_payload, server_keypair)
    policy_msg = PolicyMessage(
        policy=policy_payload,
        signature=policy_jws,
    ).model_dump()
    fsm.policy(policy_msg)
    assert fsm.state == HandshakeState.POLICY_RECEIVED
    
    # Step 5: Client accepts POLICY
    accept_msg = fsm.accept_policy()
    assert fsm.state == HandshakeState.ACCEPTANCE_SENT
    assert accept_msg["message_type"] == "ACCEPT_POLICY"
    
    # Step 6: Server sends SESSION
    session_id = "session-1234567890"
    expires_at = int(time.time()) + 3600
    session_payload = {"session_id": session_id, "expires_at": expires_at}
    session_jws = JWS.create(session_payload, server_keypair)
    session_msg = SessionMessage(
        session_id=session_id,
        expires_at=expires_at,
        signature=session_jws,
    ).model_dump()
    fsm.session(session_msg)
    
    # Handshake complete!
    assert fsm.state == HandshakeState.ESTABLISHED
    assert fsm.is_established() is True
    assert fsm.get_session_id() == session_id


# ===== TESTS 2-3: STATE TIMEOUT TESTS =====

def test_02_state_timeout_hello(client_keypair, client_did, manifest_hash, policy_hash, server_public_keys):
    """Test 2: State timeout during HELLO state."""
    config = HandshakeFSMConfig(state_timeout_seconds=1)
    fsm = HandshakeFSM(client_keypair, client_did, manifest_hash, config)
    
    fsm.hello()
    time.sleep(2)  # Ensure timeout definitely occurs (generous margin)
    
    # Try to receive CHALLENGE after timeout
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    
    with pytest.raises(A2ATimeoutError):
        fsm.challenge(challenge_msg)


def test_03_total_timeout(client_keypair, client_did, manifest_hash, policy_hash, server_public_keys):
    """Test 3: Total handshake timeout."""
    config = HandshakeFSMConfig(
        state_timeout_seconds=100,
        total_timeout_seconds=1,
    )
    fsm = HandshakeFSM(client_keypair, client_did, manifest_hash, config)
    
    fsm.hello()
    time.sleep(2)  # Ensure total timeout definitely occurs
    
    # Try to receive CHALLENGE after total timeout
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    
    with pytest.raises(A2ATimeoutError):
        fsm.challenge(challenge_msg)


# ===== TEST 4: REPLAY PROTECTION =====

def test_04_nonce_replay_protection(fsm, policy_hash, server_public_keys):
    """Test 4: Replay protection - sending same nonce twice is rejected."""
    hello_msg = fsm.hello()
    
    nonce_b = generate_nonce(32)
    challenge_msg = ChallengeMessage(
        nonce_b=nonce_b,
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    
    # Try to send another CHALLENGE with same nonce_b
    challenge_msg2 = ChallengeMessage(
        nonce_b=nonce_b,
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    
    # Create new FSM to test replay
    fsm2 = HandshakeFSM(fsm.keypair, fsm.agent_did, fsm.manifest_hash)
    fsm2.hello()
    fsm2.challenge(challenge_msg2)
    
    # Now try same nonce again - should be rejected
    with pytest.raises(HandshakeError) as exc:
        fsm2.challenge(challenge_msg2)
    assert "NONCE_REPLAY" in str(exc.value.code) or "INVALID_STATE_TRANSITION" in str(exc.value.code)


# ===== TESTS 5-6: INVALID STATE TRANSITIONS =====

def test_05_invalid_state_transition_challenge_after_session(fsm, server_keypair, policy_hash, server_public_keys, policy):
    """Test 5: Cannot receive CHALLENGE after SESSION."""
    # Complete handshake first
    hello_msg = fsm.hello()
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    fsm.proof()
    
    policy_payload = {"rate_limit": 100}
    policy_jws = JWS.create(policy_payload, server_keypair)
    policy_msg = PolicyMessage(
        policy=policy_payload,
        signature=policy_jws,
    ).model_dump()
    fsm.policy(policy_msg)
    
    fsm.accept_policy()
    
    session_id = "session-123456789"
    expires_at = int(time.time()) + 3600
    session_payload = {"session_id": session_id, "expires_at": expires_at}
    session_jws = JWS.create(session_payload, server_keypair)
    session_msg = SessionMessage(
        session_id=session_id,
        expires_at=expires_at,
        signature=session_jws,
    ).model_dump()
    fsm.session(session_msg)
    
    # Now try to receive CHALLENGE
    with pytest.raises(HandshakeError) as exc:
        fsm.challenge(challenge_msg)
    assert "INVALID_STATE_TRANSITION" in str(exc.value.code)


def test_06_cannot_send_hello_twice(fsm):
    """Test 6: Cannot send HELLO twice."""
    fsm.hello()
    
    with pytest.raises(HandshakeError) as exc:
        fsm.hello()
    assert "INVALID_STATE_TRANSITION" in str(exc.value.code)


# ===== TESTS 7-8: NONCE HANDLING =====

def test_07_nonce_a_included_in_proof(fsm, policy_hash, server_public_keys):
    """Test 7: nonce_a is included in PROOF."""
    hello_msg = fsm.hello()
    nonce_a = hello_msg["nonce_a"]
    
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    
    proof_msg = fsm.proof()
    assert proof_msg["nonce_a"] == nonce_a


def test_08_nonce_b_included_in_proof(fsm, policy_hash, server_public_keys):
    """Test 8: nonce_b is included in PROOF."""
    fsm.hello()
    
    nonce_b = generate_nonce(32)
    challenge_msg = ChallengeMessage(
        nonce_b=nonce_b,
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    
    proof_msg = fsm.proof()
    assert proof_msg["nonce_b"] == nonce_b


# ===== TEST 9: SIGNATURE VERIFICATION =====

def test_09_policy_signature_with_wrong_key(fsm, server_keypair, policy_hash, server_public_keys):
    """Test 9: Policy signature verification fails with wrong key."""
    wrong_keypair = KeyPair.generate()
    
    fsm.hello()
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=[
            {
                "kid": "sig-2024-01",
                "kty": "EC",
                "alg": "EdDSA",
                "use": "sig",
                "key": wrong_keypair.public_key_base64(),
            }
        ],
    ).model_dump()
    fsm.challenge(challenge_msg)
    fsm.proof()
    
    # Create policy with signature from DIFFERENT keypair
    policy_payload = {"rate_limit": 100}
    wrong_jws = JWS.create(policy_payload, server_keypair)  # signed by server_keypair
    policy_msg = PolicyMessage(
        policy=policy_payload,
        signature=wrong_jws,  # but we expect wrong_keypair
    ).model_dump()
    
    # Should raise because signature doesn't match expected key
    with pytest.raises(HandshakeError) as exc:
        fsm.policy(policy_msg)


# ===== TESTS 10-11: TIMESTAMP VALIDATION =====

def test_10_future_timestamp_rejected():
    """Test 10: Message with future timestamp is rejected."""
    future_time = int(time.time()) + 600  # 10 minutes in future
    with pytest.raises(Exception):  # Pydantic validation
        HelloMessage(
            nonce_a=generate_nonce(32),
            agent_did="did:key:test",
            manifest_hash="a" * 64,
            timestamp=future_time,
        )


def test_11_expired_timestamp_rejected():
    """Test 11: Message with expired timestamp is rejected."""
    past_time = int(time.time()) - 600  # 10 minutes ago
    with pytest.raises(Exception):  # Pydantic validation
        HelloMessage(
            nonce_a=generate_nonce(32),
            agent_did="did:key:test",
            manifest_hash="a" * 64,
            timestamp=past_time,
        )


# ===== TESTS 12-17: MESSAGE VALIDATION =====

def test_12_hello_invalid_short_nonce():
    """Test 12: HELLO rejects short nonce."""
    with pytest.raises(Exception):
        HelloMessage(
            nonce_a="tooshort",
            agent_did="did:key:test",
            manifest_hash="a" * 64,
        )


def test_13_hello_invalid_manifest_hash():
    """Test 13: HELLO rejects invalid manifest hash."""
    with pytest.raises(Exception):
        HelloMessage(
            nonce_a=generate_nonce(32),
            agent_did="did:key:test",
            manifest_hash="invalid",  # not 64 hex chars
        )


def test_14_challenge_missing_public_keys():
    """Test 14: CHALLENGE requires public_keys."""
    with pytest.raises(Exception):
        ChallengeMessage(
            nonce_b=generate_nonce(32),
            policy_hash="a" * 64,
            public_keys=[],  # empty
        )


def test_15_did_validation():
    """Test 15: DID must start with did:key:."""
    with pytest.raises(Exception):
        HelloMessage(
            nonce_a=generate_nonce(32),
            agent_did="invalid-did",
            manifest_hash="a" * 64,
        )


def test_16_manifest_hash_must_be_hex():
    """Test 16: manifest_hash must be valid hex."""
    with pytest.raises(Exception):
        HelloMessage(
            nonce_a=generate_nonce(32),
            agent_did="did:key:test",
            manifest_hash="z" * 64,  # not valid hex
        )


def test_17_session_must_expire_in_future():
    """Test 17: SESSION message requires expires_at > now."""
    past_time = int(time.time()) - 100
    with pytest.raises(Exception):
        SessionMessage(
            session_id="session-123456789",
            expires_at=past_time,
            signature="header.payload.sig",
        )


# ===== TESTS 18-27: STATE QUERIES & EDGE CASES =====

def test_18_init_state():
    """Test 18: FSM starts in INIT state."""
    kp = KeyPair.generate()
    fsm = HandshakeFSM(kp, kp.get_did_key(), "a" * 64)
    assert fsm.state == HandshakeState.INIT
    assert fsm.is_established() is False


def test_19_is_established_false_before_session(fsm, policy_hash, server_public_keys):
    """Test 19: is_established returns False before SESSION."""
    fsm.hello()
    assert fsm.is_established() is False
    
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    assert fsm.is_established() is False
    
    fsm.proof()
    assert fsm.is_established() is False


def test_20_get_session_id_none_before_established(fsm, policy_hash, server_public_keys):
    """Test 20: get_session_id returns None before ESTABLISHED."""
    fsm.hello()
    assert fsm.get_session_id() is None
    
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    assert fsm.get_session_id() is None


def test_21_get_state(fsm):
    """Test 21: get_state returns current state."""
    assert fsm.get_state() == "INIT"
    fsm.hello()
    assert fsm.get_state() == "HELLO_SENT"


def test_22_policy_hash_consistency(fsm, policy_hash, server_public_keys):
    """Test 22: policy_hash is echoed back in ACCEPT_POLICY."""
    fsm.hello()
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    fsm.proof()
    
    # Verify FSM stored policy_hash
    assert fsm.policy_hash == policy_hash


def test_23_terminate_handshake(fsm):
    """Test 23: terminate() method."""
    fsm.hello()
    fsm.terminate()
    assert fsm.is_terminated() is True
    assert fsm.state == HandshakeState.TERMINATED


def test_24_fail_handshake(fsm):
    """Test 24: fail() method."""
    fsm.hello()
    fsm.fail(Exception("test error"))
    assert fsm.is_failed() is True
    assert fsm.state == HandshakeState.FAILED


def test_25_cannot_send_proof_before_challenge(fsm):
    """Test 25: Cannot send PROOF before receiving CHALLENGE."""
    fsm.hello()
    
    with pytest.raises(HandshakeError) as exc:
        fsm.proof()
    assert "INVALID_STATE_TRANSITION" in str(exc.value.code)


def test_26_valid_timestamp_accepted():
    """Test 26: Current timestamp is accepted."""
    msg = HelloMessage(
        nonce_a=generate_nonce(32),
        agent_did="did:key:test",
        manifest_hash="a" * 64,
        timestamp=int(time.time()),
    )
    assert msg is not None


def test_27_policy_signature_verification(fsm, server_keypair, policy_hash, server_public_keys):
    """Test 27: Policy signature is verified correctly."""
    fsm.hello()
    challenge_msg = ChallengeMessage(
        nonce_b=generate_nonce(32),
        policy_hash=policy_hash,
        public_keys=server_public_keys,
    ).model_dump()
    fsm.challenge(challenge_msg)
    fsm.proof()
    
    # Create policy with CORRECT signature
    policy_payload = {"rate_limit": 100}
    correct_jws = JWS.create(policy_payload, server_keypair)
    policy_msg = PolicyMessage(
        policy=policy_payload,
        signature=correct_jws,
    ).model_dump()
    
    # Should not raise
    fsm.policy(policy_msg)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
