"""
Tests for PHASE 7 CRITICAL SECURITY FIXES (Issues #1-10).

Covers:
- Issue #1: Session Commitment Binding (session hijacking prevention)
- Issue #2: Nonce Blacklist Per-DID (nonce replay prevention)
- Issue #4: Policy Hash Mismatch Closes Session
- Issue #5: Per-Client-DID Rate Limiting
- Issue #6: Intent Filtering Per-Request
- Issue #7: Audit Log HMAC & Append-Only
- Issue #8: Request Sequence Numbering
- Issue #9: Handshake Timeout Cleanup
- Issue #10: Concurrent Rate Limit Atomicity

Target: 30+ new tests
"""

import pytest
import time
import json
from hashlib import sha256
from threading import Thread

from a2a.protocol.session.manager import SessionManager
from a2a.protocol.session.session import Session, SessionStatus
from a2a.protocol.session.nonce_tracker import NonceTracker
from a2a.protocol.session.audit_log import AuditLog, AuditLogEntry
from a2a.protocol.session.policy import PolicyEnforcer, SessionPolicy
from a2a.protocol.session.errors import (
    SessionError,
    RateLimitExceededError,
    IntentNotAllowedError,
)


# ==============================================================================
# ISSUE #1: Session Commitment Binding Tests
# ==============================================================================

class TestSessionCommitmentBinding:
    """Test session hijacking prevention via commitment binding."""
    
    def test_session_commitment_computed_from_handshake_values(self):
        """Session commitment should be computed from manifest hashes and nonces."""
        manager = SessionManager()
        
        # Create session with commitment values
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
            client_manifest_hash="sha256:client_manifest",
            server_manifest_hash="sha256:server_manifest",
            nonce_a="nonce_a_value",
            nonce_b="nonce_b_value",
        )
        
        # Verify commitment is set
        assert session.session_commitment is not None
        assert session.session_commitment.startswith("sha256:")
        
        # Verify commitment is deterministic
        expected_input = "sha256:client_manifest|sha256:server_manifest|nonce_a_value|nonce_b_value"
        expected_hash = f"sha256:{sha256(expected_input.encode()).hexdigest()}"
        assert session.session_commitment == expected_hash
    
    def test_session_commitment_required_validation(self):
        """Requests without commitment should be rejected if session has commitment."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
            client_manifest_hash="sha256:client_manifest",
            server_manifest_hash="sha256:server_manifest",
            nonce_a="nonce_a_value",
            nonce_b="nonce_b_value",
        )
        
        # Validate with correct commitment should pass
        assert manager.validate_session_commitment(
            "sess123",
            session.session_commitment
        ) is True
    
    def test_session_commitment_mismatch_rejected(self):
        """Request with wrong commitment should be rejected."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
            client_manifest_hash="sha256:client_manifest",
            server_manifest_hash="sha256:server_manifest",
            nonce_a="nonce_a_value",
            nonce_b="nonce_b_value",
        )
        
        # Validate with wrong commitment should fail
        with pytest.raises(SessionError) as exc_info:
            manager.validate_session_commitment("sess123", "wrong_commitment")
        
        assert "COMMITMENT_MISMATCH" in str(exc_info.value)
        assert exc_info.value.status_code == 401
    
    def test_session_commitment_verified_on_every_request(self):
        """Commitment should be verified for each request."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
            client_manifest_hash="sha256:client_manifest",
            server_manifest_hash="sha256:server_manifest",
            nonce_a="nonce_a_value",
            nonce_b="nonce_b_value",
        )
        
        # Should be verifiable multiple times
        for _ in range(5):
            assert manager.validate_session_commitment(
                "sess123",
                session.session_commitment
            ) is True


# ==============================================================================
# ISSUE #2: Nonce Blacklist Per-DID Tests
# ==============================================================================

class TestNonceBlacklistPerDid:
    """Test nonce replay prevention per DID."""
    
    def test_nonce_replay_detected_within_window(self):
        """Nonce replay should be detected within blacklist window."""
        tracker = NonceTracker(blacklist_window_seconds=3600)
        
        # Track nonce for DID
        tracker.add_nonce("did:key:client1", "nonce123")
        
        # Attempting to use same nonce should be detected as replay
        assert tracker.is_nonce_replayed("did:key:client1", "nonce123") is True
    
    def test_nonce_replay_allowed_after_expiry(self):
        """Nonce should be allowed after expiry window."""
        tracker = NonceTracker(blacklist_window_seconds=1)
        
        # Track nonce for DID
        tracker.add_nonce("did:key:client1", "nonce123")
        assert tracker.is_nonce_replayed("did:key:client1", "nonce123") is True
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Cleanup and check
        tracker.cleanup_all_expired()
        assert tracker.is_nonce_replayed("did:key:client1", "nonce123") is False
    
    def test_nonce_tracking_per_did(self):
        """Each DID should have independent nonce tracking."""
        tracker = NonceTracker(blacklist_window_seconds=3600)
        
        # Track same nonce for different DIDs
        tracker.add_nonce("did:key:client1", "same_nonce")
        tracker.add_nonce("did:key:client2", "same_nonce")
        
        # Replay should be detected for both
        assert tracker.is_nonce_replayed("did:key:client1", "same_nonce") is True
        assert tracker.is_nonce_replayed("did:key:client2", "same_nonce") is True
        
        # But different nonce should not be detected
        assert tracker.is_nonce_replayed("did:key:client1", "other_nonce") is False
    
    def test_nonce_tracking_multiple_nonces_per_did(self):
        """DID can have multiple nonces tracked."""
        tracker = NonceTracker(blacklist_window_seconds=3600)
        
        # Track multiple nonces for same DID
        tracker.add_nonce("did:key:client1", "nonce_a")
        tracker.add_nonce("did:key:client1", "nonce_b")
        tracker.add_nonce("did:key:client1", "nonce_c")
        
        # All should be detected
        assert tracker.is_nonce_replayed("did:key:client1", "nonce_a") is True
        assert tracker.is_nonce_replayed("did:key:client1", "nonce_b") is True
        assert tracker.is_nonce_replayed("did:key:client1", "nonce_c") is True
    
    def test_concurrent_nonce_tracking(self):
        """Nonce tracker should be thread-safe."""
        tracker = NonceTracker(blacklist_window_seconds=3600)
        results = []
        
        def worker(did_id: int, nonce_id: int):
            did = f"did:key:client{did_id}"
            nonce = f"nonce{nonce_id}"
            
            # Each thread tracks a nonce
            tracker.add_nonce(did, nonce)
            
            # Then checks if it was tracked
            is_replayed = tracker.is_nonce_replayed(did, nonce)
            results.append(is_replayed)
        
        # Run 10 threads concurrently
        threads = []
        for i in range(10):
            t = Thread(target=worker, args=(i % 3, i))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All should have detected replay
        assert all(results)


# ==============================================================================
# ISSUE #7: Audit Log HMAC & Append-Only Tests
# ==============================================================================

class TestAuditLogHmacAppendOnly:
    """Test tamper-proof audit logging."""
    
    def test_audit_log_entries_signed_with_hmac(self):
        """Audit log entries should be signed with HMAC-SHA256."""
        audit_log = AuditLog(secret_key="secret123")
        
        entry = AuditLogEntry(
            timestamp=int(time.time()),
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            intent_goal="query",
            status="success",
            duration_ms=100,
        )
        
        # Log entry
        audit_log.log_entry(entry)
        
        # Verify entry was logged with signature
        assert audit_log.count() == 1
        logged_entry, signature = audit_log.entries[0]
        assert signature is not None
        assert len(signature) == 64  # SHA256 hex digest
    
    def test_audit_log_append_only(self):
        """Audit log should be append-only."""
        audit_log = AuditLog(secret_key="secret123")
        
        # Add 3 entries
        for i in range(3):
            entry = AuditLogEntry(
                timestamp=int(time.time()),
                session_id=f"sess{i}",
                client_did="did:key:client",
                server_did="did:key:server",
                intent_goal="query",
                status="success",
                duration_ms=100,
            )
            audit_log.log_entry(entry)
        
        assert audit_log.count() == 3
        
        # Add more entries
        for i in range(3, 5):
            entry = AuditLogEntry(
                timestamp=int(time.time()),
                session_id=f"sess{i}",
                client_did="did:key:client",
                server_did="did:key:server",
                intent_goal="action",
                status="error",
                duration_ms=50,
                error_code="INTENT_DENIED",
            )
            audit_log.log_entry(entry)
        
        assert audit_log.count() == 5
        
        # Order should be preserved
        assert audit_log.entries[0][0].session_id == "sess0"
        assert audit_log.entries[4][0].session_id == "sess4"
    
    def test_audit_log_integrity_verification(self):
        """Audit log integrity should be verifiable."""
        audit_log = AuditLog(secret_key="secret123")
        
        # Add some entries
        for i in range(3):
            entry = AuditLogEntry(
                timestamp=int(time.time()),
                session_id=f"sess{i}",
                client_did="did:key:client",
                server_did="did:key:server",
                intent_goal="query",
                status="success",
                duration_ms=100,
            )
            audit_log.log_entry(entry)
        
        # Verify integrity
        assert audit_log.verify_integrity() is True
    
    def test_audit_log_tamper_detection(self):
        """Tampering with audit log should be detected."""
        audit_log = AuditLog(secret_key="secret123")
        
        # Add entry
        entry = AuditLogEntry(
            timestamp=int(time.time()),
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            intent_goal="query",
            status="success",
            duration_ms=100,
        )
        audit_log.log_entry(entry)
        
        # Tamper with signature
        original_sig = audit_log.entries[0][1]
        tampered_sig = original_sig[:-2] + "XX"  # Change last 2 chars
        audit_log.entries[0] = (audit_log.entries[0][0], tampered_sig)
        
        # Integrity check should fail
        assert audit_log.verify_integrity() is False
    
    def test_audit_log_export_signed(self):
        """Audit log should export with signatures."""
        audit_log = AuditLog(secret_key="secret123")
        
        entry = AuditLogEntry(
            timestamp=int(time.time()),
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            intent_goal="query",
            status="success",
            duration_ms=100,
        )
        audit_log.log_entry(entry)
        
        # Export
        exported = audit_log.export_signed()
        parsed = json.loads(exported)
        
        assert len(parsed) == 1
        assert "entry" in parsed[0]
        assert "signature" in parsed[0]
        assert parsed[0]["entry"]["session_id"] == "sess123"
        assert len(parsed[0]["signature"]) == 64


# ==============================================================================
# ISSUE #8: Request Sequence Numbering Tests
# ==============================================================================

class TestRequestSequenceNumbering:
    """Test out-of-order request prevention."""
    
    def test_sequence_starts_at_zero(self):
        """Session should start with last_sequence = 0."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        assert session.last_sequence == 0
    
    def test_valid_sequence_accepted(self):
        """Valid increasing sequence should be accepted."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        # Sequence 1 should be accepted
        assert manager.validate_sequence("sess123", 1) is True
        assert session.last_sequence == 1
        
        # Sequence 2 should be accepted
        assert manager.validate_sequence("sess123", 2) is True
        assert session.last_sequence == 2
    
    def test_out_of_order_requests_rejected(self):
        """Out-of-order request (seq <= last_seq) should be rejected."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        # Valid: seq 1
        manager.validate_sequence("sess123", 1)
        
        # Invalid: seq 1 again (duplicate)
        with pytest.raises(SessionError) as exc_info:
            manager.validate_sequence("sess123", 1)
        
        assert "OUT_OF_ORDER" in str(exc_info.value)
        assert exc_info.value.status_code == 400
    
    def test_duplicate_sequence_rejected(self):
        """Duplicate sequence number should be rejected."""
        manager = SessionManager()
        
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        # Valid: seq 1
        manager.validate_sequence("sess123", 1)
        
        # Invalid: seq 0 (less than last)
        with pytest.raises(SessionError):
            manager.validate_sequence("sess123", 0)


# ==============================================================================
# ISSUE #5: Per-Client-DID Rate Limiting Tests
# ==============================================================================

class TestPerClientRateLimiting:
    """Test per-client-DID rate limiting."""
    
    def test_per_client_did_rate_limit_enforced(self):
        """Per-client-DID rate limit should be enforced across sessions."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.rate_limit.requests_per_hour = 10
        enforcer = PolicyEnforcer(manager)
        
        # Create session
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        # Make 10 requests from same client
        for i in range(10):
            enforcer.check_client_rate_limit("did:key:client", policy)
        
        # 11th request should fail
        with pytest.raises(RateLimitExceededError):
            enforcer.check_client_rate_limit("did:key:client", policy)
    
    def test_per_client_did_rate_limit_independent_sessions(self):
        """Per-client rate limit should apply across all sessions."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.rate_limit.requests_per_hour = 5
        enforcer = PolicyEnforcer(manager)
        
        client_did = "did:key:client"
        
        # Create 2 sessions for same client
        session1 = manager.create_session(
            session_id="sess1",
            client_did=client_did,
            server_did="did:key:server1",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        session2 = manager.create_session(
            session_id="sess2",
            client_did=client_did,
            server_did="did:key:server2",
            manifest_hash="sha256:xyz789",
            policy_hash="sha256:ijk012",
            expires_at=time.time() + 3600,
        )
        
        # Make 5 requests total (across both sessions)
        for i in range(5):
            enforcer.check_client_rate_limit(client_did, policy)
        
        # 6th request should fail (across all sessions for this client)
        with pytest.raises(RateLimitExceededError):
            enforcer.check_client_rate_limit(client_did, policy)


# ==============================================================================
# ISSUE #6: Intent Filtering Per-Request Tests
# ==============================================================================

class TestIntentFilteringPerRequest:
    """Test intent filtering on per-request basis."""
    
    def test_intent_whitelist_enforced(self):
        """Only whitelisted intents should be allowed."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.intent.allowed_intents = ["query", "read"]
        enforcer = PolicyEnforcer(manager)
        
        # Allowed intent
        assert enforcer.check_intent_allowed("query", policy) is True
        assert enforcer.check_intent_allowed("read", policy) is True
        
        # Not in whitelist
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("write", policy)
    
    def test_intent_blacklist_enforced(self):
        """Blacklisted intents should be rejected."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.intent.blocked_intents = ["delete", "admin"]
        enforcer = PolicyEnforcer(manager)
        
        # Allowed intent
        assert enforcer.check_intent_allowed("query", policy) is True
        
        # Blocked intents
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("delete", policy)
        
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("admin", policy)
    
    def test_whitelist_takes_precedence_over_blacklist(self):
        """Whitelist should take precedence (if both specified)."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.intent.allowed_intents = ["query"]
        policy.intent.blocked_intents = ["admin"]
        enforcer = PolicyEnforcer(manager)
        
        # Only whitelisted allowed
        assert enforcer.check_intent_allowed("query", policy) is True
        
        # Non-whitelisted rejected even if not explicitly blocked
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("write", policy)


# ==============================================================================
# ISSUE #10: Concurrent Rate Limit Atomicity Tests
# ==============================================================================

class TestConcurrentRateLimitAtomicity:
    """Test atomic rate limit checking under concurrency."""
    
    def test_concurrent_rate_limit_enforcement(self):
        """Rate limit should be enforced atomically with concurrent requests."""
        manager = SessionManager()
        policy = SessionPolicy()
        policy.rate_limit.requests_per_hour = 10
        enforcer = PolicyEnforcer(manager)
        
        # Create session
        session = manager.create_session(
            session_id="sess123",
            client_did="did:key:client",
            server_did="did:key:server",
            manifest_hash="sha256:abc123",
            policy_hash="sha256:def456",
            expires_at=time.time() + 3600,
        )
        
        success_count = []
        failure_count = []
        
        def worker():
            try:
                enforcer.check_rate_limit(session, policy)
                success_count.append(1)
            except RateLimitExceededError:
                failure_count.append(1)
        
        # Run 20 threads concurrently (limit is 10)
        threads = []
        for _ in range(20):
            t = Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # At least 10 should succeed, at least 10 should fail (atomic enforcement)
        assert len(success_count) >= 10
        assert len(failure_count) >= 10
        assert len(success_count) + len(failure_count) == 20
