# A2A Protocol v1.0.0 Deployment Guide

## Prerequisites

- Python 3.9+
- TLS 1.3 or higher
- Ed25519 key pairs for DIDs
- HTTP/HTTPS server capability

## Quick Setup

```bash
# 1. Install A2A
pip install .

# 2. Create agent DIDs
python -c "from a2a.core.identity import create_did; print(create_did())"

# 3. Generate manifest hash
python -c "from a2a.core.manifest import Manifest; m = Manifest(...); print(m.hash())"

# 4. Start server
python examples/server_agent.py
```

## TLS Certificate Setup

### Production (Let's Encrypt)

```bash
# 1. Obtain certificate
certbot certonly --standalone -d agent.example.com

# 2. Configure A2A
from a2a.transport.http import HTTPTransport

transport = HTTPTransport(
    verify_tls=True,
    tls_min_version="TLSv1_3"
)

# 3. Start server with TLS
await transport.start_server(
    host="0.0.0.0",
    port=443,
    tls_cert_path="/etc/letsencrypt/live/agent.example.com/fullchain.pem",
    tls_key_path="/etc/letsencrypt/live/agent.example.com/privkey.pem",
    handler=your_handler,
)
```

### Development (Self-Signed)

```bash
# 1. Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# 2. Use with verification disabled
transport = HTTPTransport(verify_tls=False)  # Development only!
```

## DID Resolution

### Method 1: DNS TXT Records (Recommended)

```bash
# 1. Publish DID in DNS TXT record
# TXT record: did.example.com = "did:key:z5U1GhkGR..."

# 2. Configure client
from a2a.core.identity import resolve_did

server_did = await resolve_did("did:example:agent@example.com")
```

### Method 2: DID Pinning (Highest Security)

```bash
# 1. Pin DID manually
CLIENT_DIDS = {
    "Server A": "did:key:z5U1GhkGR...",
    "Server B": "did:key:z6Mkq7A9...",
}

# 2. Verify before handshake
from a2a.protocol.handshake import ClientHandshakeFSM

fsm = ClientHandshakeFSM(...)
if fsm.server_public_keys[0]["id"] not in CLIENT_DIDS.values():
    raise SecurityError("DID not pinned")
```

## Audit Log Export

### Setup External Syslog

```python
from a2a.protocol.session.audit_log import AuditLog
import json
import logging

# 1. Create audit log
audit_log = AuditLog(secret_key="your-secret-key")

# 2. Configure syslog handler
import logging.handlers
handler = logging.handlers.SysLogHandler(address="/dev/log")
formatter = logging.Formatter('a2a_audit: %(message)s')
handler.setFormatter(formatter)

logger = logging.getLogger("a2a.audit")
logger.addHandler(handler)

# 3. Export regularly
def export_audit_logs():
    export_data = audit_log.export_signed()
    logger.info(export_data)
```

### Verify Audit Log Integrity

```bash
# 1. Retrieve exported logs
logs=$(grep "a2a_audit:" /var/log/syslog | tail -1)

# 2. Verify signatures
python -c "
import json
from a2a.protocol.session.audit_log import AuditLog

audit_log = AuditLog(secret_key='your-secret-key')
# Reconstruct entries from logs
for entry_data in json.loads(logs):
    stored_sig = entry_data['signature']
    entry = AuditLogEntry(**entry_data['entry'])
    expected_sig = entry.compute_signature('your-secret-key')
    assert stored_sig == expected_sig, 'Tampered!'
print('Audit log is authentic')
"
```

## Monitoring & Alerting

### Metrics to Monitor

```python
# 1. Session metrics
- active_sessions: Count of active sessions
- session_creation_rate: Sessions per minute
- session_errors: Failed handshakes per minute

# 2. Rate limit metrics
- rate_limit_violations: Requests rejected for rate limiting
- rate_limit_by_client: Per-client-DID violation rate

# 3. Security metrics
- commitment_mismatches: Session commitment validation failures
- nonce_replays: Nonce replay detection events
- sequence_violations: Out-of-order request rejections
- policy_violations: Intent filtering rejections

# 4. Audit log metrics
- audit_log_entries_per_hour
- audit_log_verification_status
```

### Alert Thresholds

```python
# AlertManager configuration
ALERTS = {
    "rate_limit_violation_spike": {
        "condition": "rate_limit_violations > 100 per minute",
        "severity": "high",
        "action": "notify_security_team"
    },
    "nonce_replay_detected": {
        "condition": "nonce_replay_attempts > 10 per hour",
        "severity": "critical",
        "action": "block_client"
    },
    "sequence_violation_spike": {
        "condition": "sequence_violations > 50 per minute",
        "severity": "high",
        "action": "investigate_client"
    },
    "audit_log_tamper_detected": {
        "condition": "audit_log.verify_integrity() == False",
        "severity": "critical",
        "action": "alert_immediately"
    },
}
```

## Rate Limiting Configuration

### Default Values (Recommended for Production)

```python
from a2a.protocol.session.policy import SessionPolicy, RateLimitPolicy

policy = SessionPolicy()
policy.rate_limit = RateLimitPolicy(
    requests_per_second=10,      # Per session
    requests_per_minute=600,     # Per session
    requests_per_hour=36000,     # Per session (10 req/sec * 3600)
)

# Per-client-DID limits (Issue #5)
policy.rate_limit_per_client_did = RateLimitPolicy(
    requests_per_second=50,      # Across all sessions for client
    requests_per_minute=3000,    # Across all sessions for client
    requests_per_hour=180000,    # Across all sessions for client
)
```

### Tuning for Your Infrastructure

```python
# Light load (< 100 concurrent sessions)
policy.rate_limit.requests_per_second = 50
policy.rate_limit.requests_per_hour = 180000

# Medium load (100-1000 concurrent sessions)
policy.rate_limit.requests_per_second = 10
policy.rate_limit.requests_per_hour = 36000

# High load (> 1000 concurrent sessions)
policy.rate_limit.requests_per_second = 5
policy.rate_limit.requests_per_hour = 18000
```

## Security Checklist

Before deploying to production:

- ✅ Use TLS 1.3 with valid certificates
- ✅ Pin server DIDs or use secure DNS resolution
- ✅ Enable audit logging and export to external syslog
- ✅ Set up monitoring and alerting for security metrics
- ✅ Configure rate limits appropriate for your load
- ✅ Review and configure intent filtering policies
- ✅ Test handshake timeout handling (30-second limit)
- ✅ Verify session commitment validation works
- ✅ Backup and securely store audit log secret keys
- ✅ Plan for nonce blacklist storage (1-hour window per DID)
- ✅ Test concurrent request handling under load
- ✅ Configure concurrent session limits per client

## Troubleshooting

### Session Commitment Mismatch

```
Error: SESSION_COMMITMENT_MISMATCH (401)
```

**Cause:** Client sending wrong commitment or manifests changed mid-session

**Fix:**
1. Verify client/server manifests haven't changed
2. Restart the session (handshake must complete fresh)
3. Check for network man-in-the-middle

### Nonce Replay Detected

```
Error: NONCE_REPLAY_DETECTED
```

**Cause:** Client reused a nonce within 1-hour window

**Fix:**
1. Clear nonce blacklist (only in development)
2. Wait 1 hour for nonce to expire
3. Investigate client for potential compromise

### Rate Limit Exceeded

```
Error: Rate limit exceeded: 10 per second (503)
```

**Cause:** Client exceeds rate limit

**Fix:**
1. Increase rate limit threshold if legitimate
2. Implement client-side backoff
3. Check for DDoS attacks (monitor rate_limit_violations)

### Handshake Timeout

```
Error: HANDSHAKE_TIMEOUT (Handshake exceeded 30s limit)
```

**Cause:** Handshake took > 30 seconds

**Fix:**
1. Check network latency
2. Increase timeouts if needed (requires code change)
3. Check server/client processing delays

## Performance Tuning

### Thread Pool Size

```python
# For HTTP server with concurrent requests
import asyncio

# Default: 10 workers
executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)

# Higher concurrency needs more workers
policy.concurrency.max_concurrent_sessions = 1000
executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
```

### Session Manager Memory

```python
# Session cleanup strategy
from a2a.protocol.session.manager import SessionManager

manager = SessionManager()

# Periodically cleanup expired sessions
async def cleanup_expired_sessions():
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        expired_count = manager.cleanup_expired()
        logger.info(f"Cleaned up {expired_count} expired sessions")
```

## Reference

- Full specification: See `a2a/protocol/`
- Example agents: `examples/`
- Test suite: `tests/`
- Threat model: `THREAT_MODEL.md`
