# A2A Protocol — Agent-to-Agent Infrastructure

**Version:** 1.0.0 (Release Candidate)  
**Status:** Reference Implementation (Production-Ready Architecture)  
**License:** MIT (Recommended for open standards)  

---

## WHAT THIS IS

A2A is a **formal protocol specification and reference implementation for agent-to-agent communication**. It defines:

- **Identity:** Cryptographically bound agent identifiers (DIDs)
- **Discovery:** How agents find each other across networks
- **Transport:** Abstract messaging layer (HTTP, gRPC, WebSocket compatible)
- **Handshake:** Cryptographic verification and policy negotiation
- **Session:** Authenticated, audited request/response lifecycle
- **Policy:** Declarative agent constraints (rate limits, capabilities, permissions)

Think of it as **the HTTP/TLS/DNS for AI agents** — the foundational infrastructure that allows millions of autonomous agents to interact safely, verifiably, and at scale.

---

## WHAT THIS IS NOT

- ❌ A **framework** — Use with any agent system (LLM, symbolic, hybrid)
- ❌ A **SaaS platform** — Fully decentralized, peer-to-peer
- ❌ A **centralized registry** — Discovery is federated and extensible
- ❌ **Opinionated about agents** — Works with any AI backend
- ❌ **Closed to other systems** — Vendor-neutral, open standard

---

## WHY IT MATTERS

### The Problem

Today, agent-to-agent communication is **fragmented and unsafe**:

- No standard identity or authentication
- Ad-hoc messaging formats
- No way to declare capabilities or constraints
- Trust is manual and fragile
- No audit trail for compliance
- Cannot verify agent authenticity at scale

This breaks the ability to build **autonomous networks of agents** in production.

### The Solution

A2A provides the **minimum necessary infrastructure** to enable:

✅ **Safe agent networks** — Cryptographic identity + policy enforcement  
✅ **Interoperability** — Standard protocol, pluggable transports  
✅ **Auditability** — Full trace of agent interactions  
✅ **Scalability** — Decentralized discovery, no central bottleneck  
✅ **Trust chains** — Reputation and endorsements  

---

## HOW AGENTS INTERACT (End-to-End)

### Scenario: Agent A calls Agent B

```
Agent A                                    Agent B
  │
  ├─ 1. Discover Agent B                    
  │      (find endpoint via DNS, IPFS, etc.)
  │
  ├─ 2. Fetch Agent B's Manifest            
  │      (signed identity card)
  │
  ├─ 3. Verify signature                    
  │      (confirm B is who it claims)       
  │
  ├─ 4. Initiate Handshake ──────────────► (HELLO: identity, nonce, public key)
  │                                         
  │ ◄─────────────────────────────────── (CHALLENGE: server nonce, policy hash)
  │
  ├─ 5. Prove identity ──────────────────► (PROOF: signed nonce proof)
  │
  │ ◄─────────────────────────────────── (POLICY: binding agreement)
  │
  ├─ 6. Accept policy ───────────────────► (ACCEPT: policy acknowledgment)
  │
  │ ◄─────────────────────────────────── (SESSION: session_id, expiry, encryption params)
  │
  ├─ 7. Send Intent ─────────────────────► (REQUEST: signed goal + inputs)
  │      (within policy constraints)
  │
  │ ◄─────────────────────────────────── (RESPONSE: result, status, audit)
  │
  └─ 8. Terminate Session               ──► (CLOSE: cleanup)
  
[All communication encrypted with TLS 1.3]
[Signatures verified with B's public key from manifest]
[Rate limiting enforced server-side]
```

---

## ARCHITECTURE

### Layered Design

```
┌──────────────────────────────────────────────────┐
│ Application Layer                                │
│ (Agent implementation, business logic)           │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ A2A Protocol Layer                               │
│ ├─ Identity (DIDs, manifests, credentials)      │
│ ├─ Discovery (DID resolution, manifest fetching)│
│ ├─ Handshake (authentication, policy exchange)  │
│ ├─ Session (lifecycle, state machine)           │
│ └─ Policy (enforcement, rate limiting)          │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ Transport Abstraction Layer (TAL)                │
│ (pluggable: HTTP/gRPC/WebSocket/custom)         │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ Network Layer (TLS 1.3 required)                 │
│ (encryption, confidentiality, integrity)        │
└──────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Protocol-first** — Specification before code
2. **Decentralized** — No single point of failure
3. **Composable** — Each layer is independent
4. **Extensible** — Transport, discovery, auth methods pluggable
5. **Auditable** — Every interaction logged
6. **Secure by default** — TLS required, signatures mandatory
7. **Standards-aligned** — Based on proven crypto (EdDSA, JWS, TLS 1.3)

---

## REPOSITORY STRUCTURE

```
a2a-protocol/
├── README.md                          (this file)
├── LICENSE                            (MIT)
├── CONTRIBUTING.md                    (contributor guidelines)
├── SECURITY.md                        (security policy)
│
├── spec/                              (FORMAL SPECIFICATION)
│   ├── A2A_PROTOCOL_v1.md             (protocol definition)
│   ├── AGENT_IDENTITY.md              (DID + manifest spec)
│   ├── SECURITY_MODEL.md              (threat model + trust)
│   ├── MESSAGE_ENVELOPE.md            (JWS + TLS binding)
│   └── ERROR_CODES.md                 (standard error catalog)
│
├── docs/                              (DOCUMENTATION)
│   ├── ARCHITECTURE.md                (layered design)
│   ├── QUICKSTART.md                  (for new implementers)
│   ├── DEPLOYMENT.md                  (operational guide)
│   ├── INTEROP.md                     (testing & compatibility)
│   └── adr/                           (architecture decision records)
│       ├── ADR-001-DID-Based-Identity.md
│       ├── ADR-002-Transport-Abstraction.md
│       └── ADR-003-Server-Side-Policy-Enforcement.md
│
├── reference/                         (REFERENCE IMPLEMENTATION - Python)
│   ├── a2a/                           (main package)
│   │   ├── __init__.py
│   │   ├── core/                      (foundational types)
│   │   │   ├── __init__.py
│   │   │   ├── identity.py            (DID, Agent, KeyPair)
│   │   │   ├── errors.py              (error codes)
│   │   │   ├── types.py               (common types)
│   │   │   └── fsm.py                 (state machine base)
│   │   │
│   │   ├── protocol/                  (A2A protocol layers)
│   │   │   ├── __init__.py
│   │   │   ├── handshake/             (authentication)
│   │   │   │   ├── __init__.py
│   │   │   │   ├── fsm.py             (handshake state machine)\n│   │   │   │   ├── messages.py        (HELLO, CHALLENGE, etc.)\n│   │   │   │   └── verification.py    (signature checking)\n│   │   │   │\n│   │   │   ├── discovery/             (agent finding)\n│   │   │   │   ├── __init__.py\n│   │   │   │   ├── fsm.py             (discovery flow)\n│   │   │   │   ├── backends.py        (DID resolution backends)\n│   │   │   │   └── cache.py           (manifest caching)\n│   │   │   │\n│   │   │   ├── session/               (ongoing communication)\n│   │   │   │   ├── __init__.py\n│   │   │   │   ├── fsm.py             (session lifecycle)\n│   │   │   │   ├── manager.py         (session pool)\n│   │   │   │   └── messages.py        (Intent, Result)\n│   │   │   │\n│   │   │   └── verification/          (manifest validation)\n│   │   │       ├── __init__.py\n│   │   │       ├── manifest.py        (manifest integrity)\n│   │   │       ├── signatures.py      (JWS verification)\n│   │   │       └── trust.py           (trust chain evaluation)\n│   │   │\n│   │   ├── transport/                 (pluggable transports)\n│   │   │   ├── __init__.py\n│   │   │   ├── base.py                (Transport ABC)\n│   │   │   ├── http.py                (HTTP/1.1 + 2)\n│   │   │   └── adapters/              (gRPC, WebSocket, etc.)\n│   │   │\n│   │   ├── security/                  (trust & policy)\n│   │   │   ├── __init__.py\n│   │   │   ├── crypto.py              (cryptographic ops)\n│   │   │   ├── policy.py              (policy definition & enforcement)\n│   │   │   └── audit.py               (structured logging)\n│   │   │\n│   │   ├── config/                    (configuration)\n│   │   │   ├── __init__.py\n│   │   │   └── schema.py              (Pydantic models)\n│   │   │\n│   │   └── agent.py                   (high-level Agent API)\n│   │\n│   ├── tests/                         (TEST SUITE)\n│   │   ├── conftest.py                (pytest fixtures)\n│   │   ├── unit/                      (unit tests)\n│   │   │   ├── test_identity.py\n│   │   │   ├── test_crypto.py\n│   │   │   └── test_fsm.py\n│   │   ├── integration/               (end-to-end tests)\n│   │   │   ├── test_handshake.py\n│   │   │   ├── test_session.py\n│   │   │   └── test_e2e.py\n│   │   ├── compliance/                (protocol compliance)\n│   │   │   └── test_message_formats.py\n│   │   └── fixtures/                  (test data)\n│   │       └── agents.py\n│   │\n│   ├── examples/                      (EXAMPLE IMPLEMENTATIONS)\n│   │   ├── simple_agent.py            (minimal agent)\n│   │   ├── echo_server.py             (simple echo service)\n│   │   └── multi_agent.py             (agent network)\n│   │\n│   ├── requirements.txt\n│   ├── pyproject.toml\n│   └── Makefile                       (build, test, lint)\n│\n├── .github/                           (CI/CD)\n│   └── workflows/\n│       ├── test.yml                   (automated testing)\n│       └── release.yml                (version tagging)\n│\n└── ROADMAP.md                         (version plan to v2.0)\n```

---

## QUICK START

### For Protocol Engineers

Read in this order:
1. **spec/A2A_PROTOCOL_v1.md** — Formal protocol definition
2. **spec/AGENT_IDENTITY.md** — Identity and manifest format
3. **spec/SECURITY_MODEL.md** — Trust and threat model
4. **docs/ARCHITECTURE.md** — Layered design

### For Reference Implementers

1. Clone this repository
2. Install dependencies: `pip install -e reference/`
3. Run tests: `cd reference && make test`
4. Study `reference/examples/simple_agent.py`
5. Read `docs/QUICKSTART.md`

### For Infrastructure Operators

1. Read `docs/DEPLOYMENT.md`
2. Review security policies in `SECURITY.md`
3. Understand policy enforcement in `spec/A2A_PROTOCOL_v1.md` (Section 7)

---

## PROTOCOL MATURITY

| Aspect | Status | Notes |
|--------|--------|-------|
| **Specification** | ✅ RC | Formal protocol spec complete |
| **Reference Implementation** | ✅ RC | Python reference, all major components |
| **Interoperability Tests** | 🟡 Planned | Skeleton present, community implementations needed |
| **Security Audit** | 🟡 Recommended | Self-review complete, 3rd-party audit suggested |
| **Production Deployments** | 🟡 Encouraged | With caveats: see SECURITY.md |

---

## WHO SHOULD USE THIS?

✅ **Build infrastructure** for autonomous agent networks  
✅ **Implement clients** in your preferred language  
✅ **Deploy services** that agents can discover and call  
✅ **Study protocols** for inspiration or standards work  
✅ **Contribute** to improving the specification  

---

## COMPARISON TO EXISTING WORK

| Project | Scope | Comparison to A2A |
|---------|-------|-------------------|
| **gRPC** | RPC protocol | A2A is more decentralized, identity-first |
| **HTTP** | Application protocol | A2A adds agent identity + policy layers |
| **TLS** | Transport security | A2A is a layer above TLS |
| **DNS** | Hostname resolution | A2A adds DID resolution + discovery |
| **OAuth2** | Delegation | A2A is symmetric (not human-centric) |

A2A is designed for **agent-to-agent trust without a centralized authority**, where both parties are autonomous systems.

---

## CONTRIBUTING

1. Read **CONTRIBUTING.md** for guidelines
2. Protocol changes: Submit RFC pull request in `/spec`
3. Implementation: Contribute to `/reference` or write your own
4. Issues: Use GitHub Issues for bugs or feature requests

See **docs/adr/** for architectural decision records.

---

## GOVERNANCE

- **Specification** owned by this repository (community feedback encouraged)
- **Reference Implementation** provided as-is
- **Licensing** MIT (permissive, suitable for standards)
- **Decision Process** RFC-style (pull requests, discussion, consensus)

---

## SECURITY

⚠️ **Read SECURITY.md** before deploying to production.

Key points:
- TLS 1.3 is **mandatory** (not optional)
- Agent manifests must be **cryptographically signed**
- Server-side **policy enforcement is required**
- Audit logging must be **enabled and monitored**

---

## ROADMAP

### v1.0.0 (Current)
- ✅ Protocol specification (formal)
- ✅ Reference implementation (Python)
- ✅ Basic test suite
- ✅ Core documentation

### v1.1.0 (Next)
- 🟡 gRPC and WebSocket transports
- 🟡 Manifest caching and pinning
- 🟡 Reputation system (endorsed agents)
- 🟡 Performance optimizations

### v2.0.0 (Future)
- 🟡 Streaming/multiplexing support
- 🟡 Multi-signature manifests
- 🟡 Decentralized agent registry (IPFS)
- 🟡 Advanced trust models (Bayesian)

See **ROADMAP.md** for detailed milestones.

---

## CONTACT & RESOURCES

- 📖 **Specification:** `/spec/*.md`
- 💬 **Discussion:** GitHub Issues
- 🔒 **Security Issues:** See SECURITY.md for responsible disclosure
- 📚 **Examples:** `/reference/examples/`

---

## LICENSE

MIT License — Free for commercial and open-source use.

See LICENSE file for details.

---

**A2A Protocol: Internet infrastructure for agent networks.**

Making agent-to-agent communication safe, verifiable, and interoperable at scale.

Last updated: 2026-02-07  
Status: Release Candidate v1.0.0
