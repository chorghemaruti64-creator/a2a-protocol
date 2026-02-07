"""
Unit tests for session management and policy enforcement.

Tests cover:
- Session creation with correct fields
- Session validation (active, expired, closed)
- Message count increment
- Expiry detection and cleanup
- Rate limiting (allow/reject cases)
- Intent filtering (allow/deny lists)
- Payload size validation
- Concurrent session limits
- Audit log creation + data retention
- Policy enforcement chaining
- Error responses and status codes
"""

import pytest
import time
from a2a.protocol.session import (
    Session,
    SessionStatus,
    SessionManager,
    SessionPolicy,
    PolicyEnforcer,
    RateLimitPolicy,
    IntentPolicy,
    PayloadPolicy,
    ConcurrencyPolicy,
    DataRetentionPolicy,
    AuditLog,
    # Errors
    SessionError,
    SessionNotFoundError,
    SessionExpiredError,
    SessionClosedError,
    RateLimitExceededError,
    IntentNotAllowedError,
    PayloadTooLargeError,
    TooManyConcurrentSessionsError,
)


class TestSessionCreation:
    """Test session creation and fields."""
    
    def test_session_creation_fields(self):
        """Session has correct fields after creation."""
        now = time.time()
        expires = now + 3600
        
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_manifest",
            policy_hash="hash_policy",
            created_at=now,
            expires_at=expires,
        )
        
        assert session.session_id == "test_sid"
        assert session.client_did == "did:a2a:client1"
        assert session.server_did == "did:a2a:server1"
        assert session.manifest_hash == "hash_manifest"
        assert session.policy_hash == "hash_policy"
        assert session.created_at == now
        assert session.expires_at == expires
        assert session.message_count == 0
        assert session.status == SessionStatus.ACTIVE
    
    def test_session_to_dict(self):
        """Session serializes to dictionary correctly."""
        now = time.time()
        expires = now + 3600
        
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_manifest",
            policy_hash="hash_policy",
            created_at=now,
            expires_at=expires,
        )
        
        d = session.to_dict()
        assert d['session_id'] == "test_sid"
        assert d['client_did'] == "did:a2a:client1"
        assert d['status'] == "ACTIVE"
        assert 'timestamp' not in d  # No timestamp, has created_at


class TestSessionValidation:
    """Test session validation and lifecycle."""
    
    def test_is_active_when_created(self):
        """Session is active when freshly created."""
        now = time.time()
        expires = now + 3600
        
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now,
            expires_at=expires,
        )
        
        assert session.is_active() is True
        assert session.is_expired() is False
    
    def test_is_expired_after_expiry_time(self):
        """Session is expired after expires_at timestamp."""
        now = time.time()
        # Create session that expired 1 second ago
        expires = now - 1
        
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now - 3600,
            expires_at=expires,
        )
        
        assert session.is_expired() is True
        assert session.is_active() is False
    
    def test_is_inactive_when_closed(self):
        """Session is inactive when closed."""
        now = time.time()
        expires = now + 3600
        
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now,
            expires_at=expires,
            status=SessionStatus.CLOSED,
        )
        
        assert session.is_active() is False


class TestSessionMessageCount:
    """Test message count increment."""
    
    def test_increment_message_count(self):
        """Message count increments correctly."""
        now = time.time()
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now,
            expires_at=now + 3600,
        )
        
        assert session.message_count == 0
        
        count = session.increment_message_count()
        assert count == 1
        assert session.message_count == 1
        
        count = session.increment_message_count()
        assert count == 2
        assert session.message_count == 2
    
    def test_increment_updates_last_activity(self):
        """Increment updates last_activity timestamp."""
        now = time.time()
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now,
            expires_at=now + 3600,
        )
        
        old_activity = session.last_activity
        time.sleep(0.01)  # Small delay
        session.increment_message_count()
        
        assert session.last_activity > old_activity


class TestSessionManager:
    """Test SessionManager lifecycle."""
    
    def test_create_session(self):
        """Create session with SessionManager."""
        manager = SessionManager()
        now = time.time()
        expires = now + 3600
        
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        assert session.session_id == "sid1"
        assert session.client_did == "did:a2a:client1"
        assert session.status == SessionStatus.ACTIVE
    
    def test_get_session(self):
        """Retrieve session by ID."""
        manager = SessionManager()
        now = time.time()
        expires = now + 3600
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        session = manager.get_session("sid1")
        assert session.session_id == "sid1"
    
    def test_get_session_not_found(self):
        """Raise SessionNotFoundError for missing session."""
        manager = SessionManager()
        
        with pytest.raises(SessionNotFoundError):
            manager.get_session("nonexistent")
    
    def test_validate_session_active(self):
        """Validate returns True for active session."""
        manager = SessionManager()
        now = time.time()
        expires = now + 3600
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        assert manager.validate_session("sid1") is True
    
    def test_validate_session_expired(self):
        """Validate raises SessionExpiredError for expired session."""
        manager = SessionManager()
        now = time.time()
        expires = now - 1  # Already expired
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        with pytest.raises(SessionExpiredError):
            manager.validate_session("sid1")
    
    def test_increment_message_count(self):
        """Increment message count through manager."""
        manager = SessionManager()
        now = time.time()
        expires = now + 3600
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        count = manager.increment_message_count("sid1")
        assert count == 1
        
        count = manager.increment_message_count("sid1")
        assert count == 2
    
    def test_close_session(self):
        """Close session explicitly."""
        manager = SessionManager()
        now = time.time()
        expires = now + 3600
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=expires,
        )
        
        manager.close_session("sid1")
        session = manager.get_session("sid1")
        assert session.status == SessionStatus.CLOSED
    
    def test_cleanup_expired(self):
        """Cleanup marks expired sessions."""
        manager = SessionManager()
        now = time.time()
        
        # Create active session
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        # Create expired session
        manager.create_session(
            session_id="sid2",
            client_did="did:a2a:client2",
            server_did="did:a2a:server2",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now - 1,
        )
        
        count = manager.cleanup_expired()
        assert count == 1
        
        session1 = manager.get_session("sid1")
        assert session1.status == SessionStatus.ACTIVE
        
        session2 = manager.get_session("sid2")
        assert session2.status == SessionStatus.EXPIRED


class TestRateLimiting:
    """Test rate limit enforcement."""
    
    def test_rate_limit_allow_under_limit(self):
        """Allow requests under rate limit."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            rate_limit=RateLimitPolicy(
                requests_per_second=5,
                requests_per_minute=100,
                requests_per_hour=10000,
            )
        )
        
        # Single request should be allowed
        assert enforcer.check_rate_limit(session, policy) is True
    
    def test_rate_limit_reject_per_second(self):
        """Reject when per-second limit exceeded."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            rate_limit=RateLimitPolicy(
                requests_per_second=2,
                requests_per_minute=100,
                requests_per_hour=10000,
            )
        )
        
        # First two requests OK
        enforcer.check_rate_limit(session, policy)
        enforcer.check_rate_limit(session, policy)
        
        # Third request should fail
        with pytest.raises(RateLimitExceededError):
            enforcer.check_rate_limit(session, policy)
    
    def test_rate_limit_error_status_code(self):
        """Rate limit error has 503 status code."""
        try:
            raise RateLimitExceededError(10, "per second")
        except RateLimitExceededError as e:
            assert e.status_code == 503


class TestIntentFiltering:
    """Test intent allow/deny lists."""
    
    def test_intent_allowed_no_restrictions(self):
        """Allow intent when no restrictions."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            intent=IntentPolicy(
                allowed_intents=[],
                blocked_intents=[],
            )
        )
        
        assert enforcer.check_intent_allowed("read_data", policy) is True
    
    def test_intent_allowed_in_whitelist(self):
        """Allow intent in allowed_intents list."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            intent=IntentPolicy(
                allowed_intents=["read_data", "write_data"],
                blocked_intents=[],
            )
        )
        
        assert enforcer.check_intent_allowed("read_data", policy) is True
        assert enforcer.check_intent_allowed("write_data", policy) is True
    
    def test_intent_rejected_not_in_whitelist(self):
        """Reject intent not in allowed_intents list."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            intent=IntentPolicy(
                allowed_intents=["read_data"],
                blocked_intents=[],
            )
        )
        
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("write_data", policy)
    
    def test_intent_rejected_in_blacklist(self):
        """Reject intent in blocked_intents list."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            intent=IntentPolicy(
                allowed_intents=[],
                blocked_intents=["delete_data"],
            )
        )
        
        with pytest.raises(IntentNotAllowedError):
            enforcer.check_intent_allowed("delete_data", policy)
    
    def test_intent_error_status_code(self):
        """Intent error has 403 status code."""
        try:
            raise IntentNotAllowedError("bad_intent", "blocked")
        except IntentNotAllowedError as e:
            assert e.status_code == 403


class TestPayloadValidation:
    """Test payload size validation."""
    
    def test_payload_under_limit(self):
        """Allow payload under size limit."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            payload=PayloadPolicy(max_payload_bytes=1000)
        )
        
        payload = b"x" * 500
        assert enforcer.check_payload_size(payload, policy) is True
    
    def test_payload_over_limit(self):
        """Reject payload over size limit."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            payload=PayloadPolicy(max_payload_bytes=1000)
        )
        
        payload = b"x" * 1001
        
        with pytest.raises(PayloadTooLargeError):
            enforcer.check_payload_size(payload, policy)
    
    def test_payload_error_status_code(self):
        """Payload error has 400 status code."""
        try:
            raise PayloadTooLargeError(2000, 1000)
        except PayloadTooLargeError as e:
            assert e.status_code == 400


class TestConcurrentSessions:
    """Test concurrent session limits."""
    
    def test_concurrent_under_limit(self):
        """Allow when under concurrent limit."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            concurrency=ConcurrencyPolicy(max_concurrent_sessions=5)
        )
        
        assert enforcer.check_concurrent_sessions("did:a2a:client1", policy) is True
    
    def test_concurrent_at_limit(self):
        """Reject when at concurrent limit."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        client_did = "did:a2a:client1"
        
        # Create 2 sessions for same client
        manager.create_session(
            session_id="sid1",
            client_did=client_did,
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        manager.create_session(
            session_id="sid2",
            client_did=client_did,
            server_did="did:a2a:server2",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        # Limit is 2, so next should fail
        policy = SessionPolicy(
            concurrency=ConcurrencyPolicy(max_concurrent_sessions=2)
        )
        
        with pytest.raises(TooManyConcurrentSessionsError):
            enforcer.check_concurrent_sessions(client_did, policy)
    
    def test_concurrent_error_status_code(self):
        """Concurrent error has 503 status code."""
        try:
            raise TooManyConcurrentSessionsError("did:a2a:client1", 5)
        except TooManyConcurrentSessionsError as e:
            assert e.status_code == 503


class TestPolicyEnforcement:
    """Test chaining of all policy checks."""
    
    def test_enforce_all_pass(self):
        """All checks pass returns (True, allowed, 200)."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            rate_limit=RateLimitPolicy(
                requests_per_second=10,
                requests_per_minute=100,
                requests_per_hour=1000,
            ),
            intent=IntentPolicy(allowed_intents=["read_data"]),
            payload=PayloadPolicy(max_payload_bytes=1000),
            concurrency=ConcurrencyPolicy(max_concurrent_sessions=5),
        )
        
        allowed, reason, status = enforcer.enforce(
            session=session,
            policy=policy,
            intent_goal="read_data",
            payload=b"x" * 100,
        )
        
        assert allowed is True
        assert status == 200
    
    def test_enforce_rate_limit_fails(self):
        """Rate limit failure returns (False, error, 503)."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            rate_limit=RateLimitPolicy(
                requests_per_second=1,  # Very low limit
                requests_per_minute=100,
                requests_per_hour=1000,
            ),
        )
        
        # Exceed rate limit
        enforcer.enforce(session, policy, "read_data", b"x" * 100)
        
        allowed, reason, status = enforcer.enforce(
            session=session,
            policy=policy,
            intent_goal="read_data",
            payload=b"x" * 100,
        )
        
        assert allowed is False
        assert status == 503
    
    def test_enforce_intent_fails(self):
        """Intent failure returns (False, error, 403)."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        now = time.time()
        session = manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        policy = SessionPolicy(
            intent=IntentPolicy(blocked_intents=["delete_data"]),
        )
        
        allowed, reason, status = enforcer.enforce(
            session=session,
            policy=policy,
            intent_goal="delete_data",
            payload=b"x" * 100,
        )
        
        assert allowed is False
        assert status == 403


class TestAuditLogging:
    """Test audit log creation and retention."""
    
    def test_log_request(self):
        """Log request entry."""
        log = AuditLog()
        
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        logs = log.get_logs()
        assert len(logs) == 1
        assert logs[0]['session_id'] == "sid1"
        assert logs[0]['status'] == "REQUEST"
    
    def test_log_response(self):
        """Log successful response."""
        log = AuditLog()
        
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        log.log_response(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        logs = log.get_logs()
        assert len(logs) == 2
        assert logs[1]['status'] == "SUCCESS"
        assert logs[1]['error_code'] is None
    
    def test_log_error(self):
        """Log failed request."""
        log = AuditLog()
        
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        log.log_error(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
            error_code=403,
            error_message="Intent not allowed",
        )
        
        logs = log.get_logs()
        assert len(logs) == 2
        assert logs[1]['status'] == "FAILURE"
        assert logs[1]['error_code'] == 403
        assert logs[1]['error_message'] == "Intent not allowed"
    
    def test_log_duration_ms(self):
        """Log includes request duration."""
        log = AuditLog()
        
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        time.sleep(0.05)  # 50ms delay
        
        log.log_response(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        logs = log.get_logs()
        assert logs[1]['duration_ms'] >= 40  # At least ~40ms
    
    def test_log_session_filter(self):
        """Filter logs by session ID."""
        log = AuditLog()
        
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        log.log_request(
            session_id="sid2",
            client_did="did:a2a:client2",
            server_did="did:a2a:server2",
            intent_goal="write_data",
        )
        
        logs = log.get_session_logs("sid1")
        assert len(logs) == 1
        assert logs[0]['session_id'] == "sid1"
    
    def test_log_cleanup_retention(self):
        """Cleanup old logs by retention period."""
        log = AuditLog()
        
        # Add old entry
        old_time = time.time() - (40 * 86400)  # 40 days ago
        from a2a.protocol.session.audit import AuditLogEntry
        old_entry = AuditLogEntry(
            timestamp=old_time,
            session_id="old_sid",
            client_did="did:a2a:old",
            server_did="did:a2a:server",
            intent_goal="test",
            status="SUCCESS",
        )
        log._entries.append(old_entry)
        
        # Add recent entry
        log.log_request(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            intent_goal="read_data",
        )
        
        assert len(log._entries) == 2
        
        # Cleanup with 30-day retention
        count = log.cleanup_by_retention(retention_days=30)
        
        assert count == 1
        assert len(log._entries) == 1


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_multiple_concurrent_sessions(self):
        """Manager handles multiple concurrent sessions."""
        manager = SessionManager()
        now = time.time()
        
        for i in range(5):
            manager.create_session(
                session_id=f"sid{i}",
                client_did=f"did:a2a:client{i}",
                server_did="did:a2a:server1",
                manifest_hash="hash_m",
                policy_hash="hash_p",
                expires_at=now + 3600,
            )
        
        assert len(manager.get_all_sessions()) == 5
    
    def test_message_count_consistency(self):
        """Message count remains consistent."""
        manager = SessionManager()
        now = time.time()
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        for i in range(1, 11):
            count = manager.increment_message_count("sid1")
            assert count == i
    
    def test_session_expiry_near_boundary(self):
        """Session expiry works at boundary."""
        now = time.time()
        # Expire exactly at "now"
        session = Session(
            session_id="test_sid",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            created_at=now,
            expires_at=now,  # Now
        )
        
        assert session.is_expired() is True
    
    def test_zero_length_payload(self):
        """Allow zero-length payload."""
        manager = SessionManager()
        enforcer = PolicyEnforcer(manager)
        
        policy = SessionPolicy(
            payload=PayloadPolicy(max_payload_bytes=1000)
        )
        
        assert enforcer.check_payload_size(b"", policy) is True
    
    def test_clear_all_sessions(self):
        """Clear all sessions for testing."""
        manager = SessionManager()
        now = time.time()
        
        manager.create_session(
            session_id="sid1",
            client_did="did:a2a:client1",
            server_did="did:a2a:server1",
            manifest_hash="hash_m",
            policy_hash="hash_p",
            expires_at=now + 3600,
        )
        
        assert len(manager.get_all_sessions()) == 1
        
        manager.clear_all()
        assert len(manager.get_all_sessions()) == 0
