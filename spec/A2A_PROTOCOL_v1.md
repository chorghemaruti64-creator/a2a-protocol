# A2A Protocol Specification v1.0

**Status:** Release Candidate  
**Date:** 2026-02-07  
**Audience:** Protocol engineers, system architects  

---

## TABLE OF CONTENTS

1. Introduction
2. Concepts & Terminology
3. Transport Layer Requirements
4. Agent Identity & Discovery
5. Handshake Protocol (A2ADP v1.0)
6. Session Protocol
7. Policy & Permission Model
8. Error Handling
9. Security Considerations
10. Interoperability & Extensions

---

## 1. INTRODUCTION

### Purpose

A2A (Agent-to-Agent) Protocol defines the minimum specification for cryptographically verified, policy-aware communication between autonomous agents in a decentralized network.

### Scope

This specification covers:
- Agent identity and manifest format
- Discovery mechanisms (DID resolution)
- Authenticated handshake with policy negotiation
- Request/response message envelopes
- Policy enforcement and audit logging
- Error model and recovery strategies

### Not in Scope

- Agent implementation (LLM, symbolic, hybrid)
- Business logic or domain-specific intents
- Specific transport implementations (those are pluggable)
- Centralized registry or governance

### Design Goals

1. **Decentralized** — No single point of trust or control
2. **Secure by default** — Cryptography mandatory, not optional
3. **Auditable** — Full trace of interactions for compliance
4. **Interoperable** — Works with any transport, any agent system
5. **Extensible** — Transport, discovery, auth methods pluggable
6. **Simple** — Minimal complexity, easy to verify correctness

---

## 2. CONCEPTS & TERMINOLOGY

### Agent

An autonomous software entity capable of:
- Receiving and understanding intents (requests)
- Making decisions about accepting/rejecting requests
- Returning results or errors
- Operating independently of human control

### Agent Manifest (Agent Card)

A signed JSON document containing:
- Agent identity (DID)
- Public cryptographic keys
- Network endpoints (where to contact the agent)
- Declared capabilities
- Policy constraints
- Trust chain/endorsements

Example:
```json
{
  "manifest_version": "1.0",
  "agent_did": "did:key:z6Mkf1234...",
  "agent_id": "translator-v1",
  "public_keys": [
    {
      "kid": "sig-2024-01",
      "kty": "EC",
      "alg": "EdDSA",
      "key": "base64url_encoded_public_key"
    }
  ],
  "endpoints": [
    {
      "type": "handshake",
      "url": "https://agent.example.com/a2a/handshake",
      "transport": "http"
    }
  ],
  "capabilities": ["nlp.translate.v1", "nlp.summarize.v1"],
  "policy": {
    "rate_limit": 1000,
    "rate_period": 3600,
    "data_retention": "24h"
  },
  "manifest_signature": "eyJ...jws_signature"
}
```

### DID (Decentralized Identifier)

A portable, cryptographic identifier for an agent. Formats:

- `did:key:z6Mk...` — Self-signed, public key embedded
- `did:web:example.com/agent/123` — DNS-backed
- `did:github:owner/repo/agent.json` — GitHub-backed

### Intent

A request from one agent to another. Structure:
```json
{
  "intent_id": "uuid-v4-correlation-id",
  "goal": "translate",
  "domain": "nlp",
  "inputs": {
    "text": "Hello",
    "target_language": "es"
  },
  "constraints": {
    "max_tokens": 100,
    "timeout_ms": 30000
  }
}
```

### Session

An authenticated, policy-governed communication channel between two agents. Includes:
- Session ID (unique identifier)
- Remote agent DID and verified manifest
- Agreed-upon policy
- Message counter for ordering
- Encryption parameters (optional)

### Policy

Constraints that an agent imposes on interactions:
```json
{
  "rate_limit": 1000,           // max requests per period
  "rate_period": 3600,          // seconds
  "session_timeout": 3600,      // seconds
  "max_payload_size": 1048576,  // bytes
  "allowed_intents": [],        // empty = all, array = whitelist
  "blocked_intents": ["delete_database"],
  "data_retention": "24h",      // none, session, 24h, 7d, 30d, permanent
  "require_encryption": false,  // optional application-layer encryption
  "max_concurrent_sessions": 100
}
```

---

## 3. TRANSPORT LAYER REQUIREMENTS

### TLS 1.3 Mandatory

All A2A communication MUST use TLS 1.3 or later:

```
Client                                Server
   │
   ├─ TLS ClientHello ─────────────────►
   │
   ◄─────────── TLS ServerHello, Cert, KE
   │
   ├─ TLS Finished ────────────────────►
   │
   ◄────────────────────── TLS Finished
   │
   ├─ A2A HELLO (encrypted) ──────────►
   │
   └─ All subsequent A2A messages encrypted
```

### Transport Abstraction

Implementations MUST support pluggable transports. Recommended:

1. **HTTP/1.1 (Required)** — Baseline support
2. **HTTP/2 (Recommended)** — Multiplexing, stream priority
3. **gRPC (Optional)** — Protobuf efficiency
4. **WebSocket (Optional)** — Real-time, bidirectional

Transport layer is opaque to protocol logic. Use adapter pattern.

### Connection Reuse

- HTTP: Keep-Alive recommended, not required
- HTTP/2: Multiplexing encouraged
- Custom: Connection pooling beneficial

---

## 4. AGENT IDENTITY & DISCOVERY

### Agent Identity (DID)

Every agent MUST have a globally unique, cryptographic identifier.

#### did:key format (self-signed)

```
did:key:z6MkiTBz1ymuqzVvQ9nsfRVnQKNJsXvW7dXbEKVTMj1Jzh7t
              └──────┬──────────────┘
              Base58-encoded public key
```

**Generation:**
```python
public_key = Ed25519_public_key()
did = "did:key:z" + Base58.encode(public_key)
```

**Resolution:** No network call required, key derived from DID directly.

#### did:web format (DNS-backed)

```
did:web:example.com:agent:translator
        │          │      │
        domain     path   agent-id
```

**Resolution:** HTTPS GET `https://example.com/.well-known/did.json`

Returns:
```json
{
  "agent_did": "did:web:example.com:agent:translator",
  "public_keys": [{ "kid": "...", "key": "...", "alg": "..." }],
  "endpoints": [{ "type": "handshake", "url": "https://..." }]
}
```

#### did:github format (GitHub-backed)

```
did:github:anthropic/a2a-reference-impl
           │         │
           owner     repo
```

**Resolution:**
1. Fetch manifest from `https://raw.githubusercontent.com/anthropic/a2a-reference-impl/main/.well-known/agent-manifest.json`
2. Verify GitHub API confirms repo is owned by claimed owner
3. Extract public key from manifest

### Agent Manifest Format

Full JSON schema in AGENT_IDENTITY.md. Key requirements:

- `manifest_version`: "1.0"
- `agent_did`: Valid DID
- `public_keys`: Array of at least one key (format: JWK)
- `endpoints`: Array of contact points (HTTP, gRPC, etc.)
- `capabilities`: List of declared abilities
- `policy`: Policy object (optional, defaults to permissive)
- `manifest_signature`: JWS signature over manifest

### Manifest Signature

Agent MUST sign its own manifest with private key.

**Signing process:**

```
canonical_manifest = sort_keys(manifest, exclude=["manifest_signature"])
payload = {
  "manifest": canonical_manifest,
  "manifest_hash": SHA256(canonical_manifest),
  "timestamp": unix_timestamp(),
  "issuer": agent_did
}
jws = JWS(payload, signing_key, alg="EdDSA")
manifest["manifest_signature"] = jws
```

**Verification:**

```
jws_parts = manifest["manifest_signature"].split(".")
payload = base64url_decode(jws_parts[1])
signature = base64url_decode(jws_parts[2])

public_key = resolve_public_key(manifest["agent_did"])
verified = verify_signature(payload, signature, public_key, alg="EdDSA")

assert verified, "Manifest signature invalid"
```

---

## 5. HANDSHAKE PROTOCOL (A2ADP v1.0)

### Overview

Handshake is a **4-step nonce-based challenge-response protocol** that:
1. Authenticates both parties
2. Negotiates policy
3. Establishes a session
4. Optionally derives a shared secret for encryption

### State Machine

```
┌─────┐
│INIT │
└──┬──┘
   │
   │ Client: initiate(server_endpoint)
   │
   ├─► TLS connect to server_endpoint
   │
   ├─► Send HELLO (client identity, nonce_a, public_key)
   │
   ◄───── Receive CHALLENGE (server nonce_b, policy_hash)
   │
   ├─► Send PROOF (signed(nonce_a | nonce_b | manifest_hash))
   │
   ◄───── Receive POLICY (policy details, policy_signature)
   │
   ├─► Send ACCEPT_POLICY (signed acceptance)
   │
   ◄───── Receive SESSION (session_id, expiry_time)
   │
   └─► ESTABLISHED ✅
   
   On timeout at any step:
   └─► FAILED ❌
```

### Message Formats (Detailed)

#### 1. HELLO (Client → Server)

```json
{
  "type": "hello",
  "protocol_version": "1.0",
  "agent_did": "did:key:z6Mk...",
  "agent_id": "client-agent-v1",
  "manifest_hash": "sha256:abc123...",
  "nonce": "random_32_bytes_base64url",
  "public_keys": [
    {
      "kid": "sig-2024-01",
      "kty": "EC",
      "alg": "EdDSA",
      "key": "base64url_public_key"
    }
  ],
  "timestamp": 1707244800,
  "user_agent": "a2a-client/1.0"
}
```

**Server Processing:**
1. Verify timestamp is recent (within 5 min)
2. Validate nonce is random (32+ bytes)
3. Store nonce_a for later verification
4. Proceed to CHALLENGE

#### 2. CHALLENGE (Server → Client)

```json
{
  "type": "challenge",
  "nonce_b": "random_server_nonce_base64url",
  "server_did": "did:key:z6Mk...",
  "manifest_hash": "sha256:server_manifest_hash",
  "public_keys": [
    {
      "kid": "sig-2024-01",
      "kty": "EC",
      "alg": "EdDSA",
      "key": "base64url"
    }
  ],
  "policy_hash": "sha256:policy_hash",
  "policy_signature": "jws_signature_of_policy",
  "timestamp": 1707244800
}
```

**Client Processing:**
1. Verify timestamp is recent
2. Verify server public key matches claimed DID
3. Store nonce_b for proof
4. Proceed to PROOF

#### 3. PROOF (Client → Server)

```json
{
  "type": "proof",
  "agent_did": "did:key:z6Mk_client",
  "proof_jws": "eyJhbGciOiJFZERTQSJ9.payload.signature"
}
```

Where proof_jws payload contains:
```json
{
  "nonce_a": "from_hello",
  "nonce_b": "from_challenge",
  "server_manifest_hash": "from_challenge",
  "client_manifest_hash": "from_hello",
  "timestamp": 1707244801
}
```

**Server Processing:**
1. Verify JWS signature with client's public key
2. Extract payload, verify both nonces match
3. Confirm manifest hashes
4. Proceed to POLICY

#### 4. POLICY (Server → Client)

```json
{
  "type": "policy",
  "policy": {
    "rate_limit": 1000,
    "rate_period": 3600,
    "session_timeout": 3600,
    "data_retention": "24h",
    "max_payload_size": 1048576,
    "allowed_intents": [],
    "blocked_intents": []
  },
  "policy_hash": "sha256:policy_content_hash",
  "policy_signature": "jws_signature_of_policy"
}
```

**Client Processing:**
1. Verify policy signature with server public key
2. Validate policy is acceptable
3. If not, reject connection
4. Proceed to ACCEPT_POLICY

#### 5. ACCEPT_POLICY (Client → Server)

```json
{
  "type": "accept_policy",
  "agent_did": "did:key:z6Mk_client",
  "policy_hash": "sha256:policy_hash_from_server",
  "acceptance_jws": "eyJ...acceptance_signature"
}
```

Where acceptance_jws payload contains:
```json
{
  "policy_hash": "from_server",
  "session_commitment": "sha256:nonce_a|nonce_b|policy_hash",
  "timestamp": 1707244802
}
```

**Server Processing:**
1. Verify acceptance signature with client public key
2. Confirm policy_hash matches
3. Verify commitment hash
4. Proceed to SESSION

#### 6. SESSION (Server → Client)

```json
{
  "type": "session",
  "session_id": "base64url_random_id",
  "server_did": "did:key:z6Mk_server",
  "created_at": 1707244800,
  "expires_at": 1707248400,
  "message_count": 0,
  "public_keys": [
    {
      "kid": "sig-2024-01",
      "kty": "EC",
      "alg": "EdDSA",
      "key": "base64url"
    }
  ]
}
```

**Client Processing:**
1. Store session_id (use in all subsequent requests)
2. Store expiry_at (reject requests after this time)
3. Verify session public keys match server
4. **HANDSHAKE COMPLETE** ✅

### Timeout Behavior

**Maximum duration:** 30 seconds

**Per-state timeouts:**
- INIT → HELLO_SENT: 5 seconds
- HELLO_SENT → CHALLENGE_RECEIVED: 10 seconds
- CHALLENGE_RECEIVED → PROOF_SENT: 10 seconds
- PROOF_SENT → POLICY_RECEIVED: 10 seconds
- POLICY_RECEIVED → ACCEPTANCE_SENT: 5 seconds
- ACCEPTANCE_SENT → SESSION_RECEIVED: 10 seconds

**On timeout:**
- Clean up session state
- Return error: `HANDSHAKE_TIMEOUT`
- Client may retry with exponential backoff

---

## 6. SESSION PROTOCOL

### Request Message

```json
{
  "type": "request",
  "session_id": "from_handshake",
  "request_id": "uuid_v4_correlation",
  "intent": {
    "goal": "translate",
    "domain": "nlp",
    "inputs": { "text": "Hello", "target_language": "es" },
    "constraints": { "max_tokens": 100, "timeout_ms": 30000 }
  },
  "request_jws": "eyJ...signature_over_intent"
}
```

**Server Processing:**
1. Verify session_id is valid and not expired
2. Verify request_id is unique (prevent replay)
3. Verify request_jws signature with client public key
4. Check rate limit for this session
5. Check intent against allowed/blocked lists
6. Check payload size < max_payload_size
7. Execute intent
8. Log audit event

### Response Message

```json
{
  "type": "response",
  "session_id": "from_request",
  "request_id": "from_request",
  "status": "success",
  "result": {
    "translated_text": "Hola",
    "language_detected": "es"
  },
  "response_jws": "eyJ...signature"
}
```

**Client Processing:**
1. Verify session_id matches
2. Verify request_id matches
3. Verify response_jws signature with server public key
4. Extract result
5. Update session timeout

### Error Response

```json
{
  "type": "error",
  "session_id": "from_request",
  "request_id": "from_request",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "error_message": "Rate limit: 1000 requests per 3600 seconds",
  "details": {
    "current_rate": 1050,
    "limit": 1000,
    "reset_at": 1707248400
  },
  "error_jws": "eyJ...signature"
}
```

---

## 7. POLICY & PERMISSION MODEL

### Policy Definition

See Section 2 (Concepts) for full policy structure.

### Enforcement Points

#### Client-Side (Advisory)

- Rate limiter token bucket
- Request ID uniqueness check
- Basic validation

#### Server-Side (Mandatory)

1. **Authentication** — Verify session is valid, agent is who it claims
2. **Rate Limiting** — Check token bucket per session
3. **Intent Filtering** — Check allowed_intents whitelist, blocked_intents blacklist
4. **Payload Validation** — Check size, signature, format
5. **Data Retention** — Enforce data lifecycle policies
6. **Audit Logging** — Log all enforcement decisions

### Example: Rate Limit Enforcement

```python
class TokenBucket:
    def __init__(self, rate: int, period: int):
        self.rate = rate        # e.g., 1000
        self.period = period    # e.g., 3600 seconds
        self.tokens = rate
        self.last_refill = time.time()
    
    def check_and_consume(self) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        
        # Refill based on elapsed time
        self.tokens += (elapsed * self.rate / self.period)
        self.tokens = min(self.tokens, self.rate)
        self.last_refill = now
        
        # Check if tokens available
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False
```

**Server Usage:**

```python
@app.post("/a2a/request")
async def handle_request(request: Request):
    session_id = request.headers["X-Session-ID"]
    session = sessions[session_id]
    
    # ENFORCE RATE LIMIT
    if not session.rate_limiter.check_and_consume():
        return ErrorResponse(
            error_code="RATE_LIMIT_EXCEEDED",
            details={
                "current_rate": calculated_rate,
                "limit": session.policy.rate_limit,
                "reset_at": session.policy.rate_period + now
            }
        )
    
    # Continue with request...
```

---

## 8. ERROR HANDLING

### Standard Error Codes

| Code | HTTP | Category | Recoverable |
|------|------|----------|-------------|
| `UNVERIFIED_AGENT` | 401 | Auth | NO |
| `INVALID_MANIFEST` | 400 | Auth | NO |
| `POLICY_VIOLATION` | 403 | Policy | NO |
| `RATE_LIMIT_EXCEEDED` | 429 | Policy | YES (wait) |
| `UNSUPPORTED_CAPABILITY` | 400 | Intent | NO |
| `INVALID_INTENT` | 400 | Intent | NO |
| `PROTOCOL_VERSION_UNSUPPORTED` | 400 | Protocol | NO |
| `HANDSHAKE_FAILED` | 500 | Handshake | YES (retry) |
| `SESSION_EXPIRED` | 401 | Session | YES (reconnect) |
| `TIMEOUT` | 504 | Transport | YES (retry) |
| `SERVICE_UNAVAILABLE` | 503 | Service | YES (retry) |
| `INTERNAL_ERROR` | 500 | Service | YES (retry) |

### Retry Strategy

**Exponential Backoff:**

```
attempt 1: wait 1s   (immediate retry)
attempt 2: wait 2s
attempt 3: wait 4s
attempt 4: wait 8s
attempt 5: wait 16s
...
max_attempts: 5
max_wait: 60s
```

**Retryable codes:** RATE_LIMIT_EXCEEDED, TIMEOUT, SERVICE_UNAVAILABLE, HANDSHAKE_FAILED, SESSION_EXPIRED

**Non-retryable codes:** UNVERIFIED_AGENT, POLICY_VIOLATION, UNSUPPORTED_CAPABILITY, INVALID_INTENT

---

## 9. SECURITY CONSIDERATIONS

### Threat Model

**Actors:**
- Agent A (client)
- Agent B (server)
- Network attacker (can intercept, modify, replay messages)
- Rogue agent (claims false identity)

**Protected Against:**

1. **Impersonation** — TLS + manifest signature verification
2. **MITM attacks** — TLS 1.3 required
3. **Replay attacks** — Nonce binding in handshake, request IDs in session
4. **Message tampering** — JWS signatures on all messages
5. **Rate abuse** — Server-side rate limiting enforced
6. **Policy bypass** — Server-side policy enforcement

**Not Protected Against:**

1. **Physical security** — Assume private keys are protected by OS
2. **Compromised agents** — Can't verify what an agent does internally
3. **DoS at network level** — Use ISP/cloud provider DoS protection

### Cryptography Standards

- **Key Generation:** EdDSA (Ed25519), must use cryptographically secure RNG
- **Signing:** JWS (JSON Web Signature) with EdDSA
- **Hashing:** SHA-256 for manifest and policy hashes
- **Encryption (Optional):** ChaCha20-Poly1305 for application-layer encryption
- **TLS:** 1.3 or later, require forward secrecy

### Key Rotation

Agents SHOULD support multiple public keys (using `kid` field). To rotate:

1. Generate new keypair
2. Add new public key to manifest with new `kid`
3. Update manifest signature
4. Keep old key for grace period (recommend 24 hours)
5. Remove old key from manifest

Clients should:
- Accept any key with valid `kid` in agent's manifest
- Cache manifest (with 1-hour TTL recommended)
- Refresh on signature verification failure

### Audit Logging

Every request MUST log:

```json
{
  "timestamp": "2026-02-07T15:00:00Z",
  "event_type": "request_received",
  "session_id": "...",
  "remote_agent_did": "did:key:...",
  "request_id": "uuid",
  "intent_goal": "translate",
  "policy_checks": {
    "rate_limit": "passed",
    "intent_allowed": "passed",
    "signature_verified": "passed"
  },
  "result": "approved",
  "response_status": "success",
  "processing_time_ms": 234
}
```

---

## 10. INTEROPERABILITY & EXTENSIONS

### Version Negotiation

Clients MAY request different protocol versions:

```json
{
  "type": "hello",
  "protocol_version": "1.0",
  "supported_versions": ["1.0"]  // optional
}
```

Server response:

```json
{
  "type": "challenge",
  "protocol_version": "1.0"  // server's chosen version
}
```

If server doesn't support client's version, return error:
```json
{
  "type": "error",
  "error_code": "PROTOCOL_VERSION_UNSUPPORTED"
}
```

### Transport Extensions

Implementations MAY support additional transports by:

1. Defining transport-specific endpoint types in manifest
2. Performing similar authentication at transport level
3. Still enforcing all policy and audit requirements

### Custom Intent Domains

While `domain` and `goal` are freeform strings, RECOMMENDED approach:

- Use reverse-DNS-style naming: `com.anthropic.nlp.translate`
- Version explicitly: `com.anthropic.nlp.translate.v2`
- Document in agent manifest's capabilities

### Custom Policy Fields

Implementations MAY add custom policy fields under `extensions`:

```json
{
  "policy": {
    "rate_limit": 1000,
    "extensions": {
      "custom_field_1": "value",
      "custom_field_2": { "nested": "data" }
    }
  }
}
```

Servers MUST ignore unknown extensions (forward-compatible).

---

## CHANGELOG

### v1.0.0 (2026-02-07) — Release Candidate

- Initial specification
- Handshake protocol finalized
- DID-based identity model
- Policy model defined
- Security model documented

---

## REFERENCES

- **TLS 1.3:** RFC 8446
- **JSON Web Signature (JWS):** RFC 7515
- **EdDSA:** RFC 8032
- **Decentralized Identifiers (DIDs):** W3C Draft
- **Base58Check:** Bitcoin-style encoding

---

**A2A Protocol v1.0 — The specification for agent-to-agent trust at scale.**
