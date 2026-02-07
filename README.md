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

## 🤖 AI Agent Prompts

### ⭐ **COMPLETE PROMPT** (Recommended)

For the most comprehensive, error-resistant prompt:

👉 **[reference/AI_AGENT_COMPLETE_PROMPT.md](reference/AI_AGENT_COMPLETE_PROMPT.md)** (32KB)

This complete prompt includes:
- ✅ Detailed step-by-step instructions (Agent Server, Client, Multi-Agent, Extensions)
- ✅ Complete code examples with full implementations
- ✅ Mandatory prerequisites and verification
- ✅ Testing requirements with code samples
- ✅ Debugging and troubleshooting guide
- ✅ Final verification checklist
- ✅ Full references to spec and guides

**Copy this prompt directly into your AI agent — it's designed to be error-resistant.**

---

### Quick Prompts (Reference)

Use these shorter prompts for quick implementation instructions:

### Prompt 1: Build A2A Agent Server

```
You are an AI assistant specialized in building secure agent services.

TASK: Implement an A2A Protocol-compliant agent server that:
1. Creates a unique DID-based identity
2. Listens for incoming A2A handshake requests
3. Handles intent requests (goals with parameters)
4. Returns properly formatted responses
5. Logs all interactions for audit trail

REQUIREMENTS:
- Use a2a-protocol>=1.0.0 library (from reference/)
- Implement cryptographic signature verification (JWS)
- Enforce TLS 1.3 in production
- Support at least 2 custom intents
- Achieve 80%+ test coverage
- Document all intents with parameters and responses

DELIVERABLES:
1. agent_server.py - Main server implementation
2. test_agent_server.py - Complete test suite
3. README.md - Quick start guide with examples
4. intents/ - Intent handler modules

REFERENCE: 
- Read: reference/PROJECT_INTEGRATION_GUIDE.md (Phase 2)
- Spec: spec/A2A_PROTOCOL_v1.md (Section 5-6)
- Example: reference/examples/simple_agent.py

START WITH: Understanding the handshake flow in README (see diagram).
```

### Prompt 2: Build A2A Agent Client

```
You are an AI assistant specialized in building secure agent clients.

TASK: Implement an A2A Protocol-compliant client that:
1. Creates its own DID-based identity
2. Discovers and connects to other agents
3. Performs cryptographic handshake
4. Sends intent requests to remote agents
5. Processes and validates responses

REQUIREMENTS:
- Use a2a-protocol>=1.0.0 library
- Implement proper error handling for all failure modes
- Support concurrent calls to multiple agents
- Cache sessions to improve performance
- Full test coverage (≥80%)
- Timeout handling (30s handshake, 10s per-state)

DELIVERABLES:
1. agent_client.py - Client implementation
2. test_agent_client.py - Test suite
3. examples/ - 2 usage examples
4. docs/CLIENT_API.md - API reference

REFERENCE:
- Read: reference/PROJECT_INTEGRATION_GUIDE.md (Phase 2)
- Spec: spec/A2A_PROTOCOL_v1.md (Section 5: Handshake FSM)
- Example: reference/examples/simple_agent.py

START WITH: Understand the 6-step handshake protocol.
```

### Prompt 3: Build Multi-Agent System

```
You are an AI architect designing a multi-agent network.

TASK: Design and implement a network of 3+ interconnected A2A agents:
1. Agent A: Data Processor (analyzes CSV data)
2. Agent B: Translator (translates text)
3. Agent C: Orchestrator (coordinates agents A and B)

REQUIREMENTS:
- All agents must be A2A v1.0.0 compliant
- Each agent has unique DID and signed manifest
- At least 3 distinct intents per agent
- Agents call each other (both client and server roles)
- Full audit logging (all interactions tracked)
- TLS 1.3 encryption for all communication
- Concurrent request handling (no blocking)

DELIVERABLES:
1. agents/ - Directory with all 3 agent implementations
2. integration_test.py - End-to-end test suite
3. docker-compose.yml - Local deployment setup
4. docs/ARCHITECTURE.md - System design diagram

REFERENCE:
- Read: reference/PROJECT_INTEGRATION_GUIDE.md (Complete Examples)
- Spec: spec/A2A_PROTOCOL_v1.md (complete)
- Example: reference/tests/integration/test_e2e.py

START WITH: Design the intent interfaces between agents.
```

### Prompt 4: Extend A2A Protocol

```
You are an AI system architect extending the A2A Protocol.

TASK: Implement a custom extension to A2A Protocol:
Options: custom transport (gRPC/WebSocket), discovery mechanism, 
reputation system, streaming support, service registry

REQUIREMENTS:
- Must be fully compliant with A2A v1.0.0 core
- No breaking changes to existing implementations
- Formal specification document required (RFC-style)
- Reference implementation in Python
- Comprehensive test suite (≥85% coverage)
- Security review documentation

DELIVERABLES:
1. SPEC.md - RFC-style specification
2. implementation/ - Reference code
3. tests/ - Complete test suite with edge cases
4. SECURITY_REVIEW.md - Threat analysis

REFERENCE:
- Spec: spec/A2A_PROTOCOL_v1.md (full reference)
- Security: spec/SECURITY_MODEL.md
- Examples: reference/a2a/ (modular structure)

SUBMIT AS: Pull request to main repository
```

### Quick Template (Copy & Customize)

```
You are an AI assistant implementing A2A Protocol agents.

TASK: [Your specific implementation goal]

A2A PROTOCOL ESSENTIALS:
- DIDs: Decentralized agent identifiers (did:key:...)
- Manifests: Cryptographically signed identity cards (JWS)
- Handshake: 6-step authenticated protocol (HELLO → CHALLENGE → PROOF → POLICY → ACCEPT → SESSION)
- Sessions: Encrypted, authenticated message exchange
- Intents: Goal-based requests with structured parameters
- Policies: Security constraints (rate limits, capability filtering)
- Audit Logging: Immutable interaction history

TECHNICAL REQUIREMENTS:
- Language: Python 3.10+
- Use: a2a-protocol>=1.0.0 library
- Crypto: Ed25519 signatures (JWS RFC 7515)
- Transport: TLS 1.3 required (production)
- Testing: 80%+ code coverage minimum
- Style: PEP 8, type hints, async/await

DOCUMENTATION REQUIRED:
- README.md with installation and examples
- CONTRIBUTING.md with code standards
- Docstrings on all public functions
- Type hints on 100% of public API
- Error handling documented

REFERENCES:
1. Specification: spec/A2A_PROTOCOL_v1.md
2. Integration Guide: reference/PROJECT_INTEGRATION_GUIDE.md
3. Examples: reference/examples/
4. Tests: reference/tests/

WORKFLOW:
1. Read specification section for your task
2. Study reference implementation
3. Write unit tests first (TDD)
4. Implement to pass tests
5. Add integration tests
6. Document API and usage
7. Run full test suite and coverage report
```

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
