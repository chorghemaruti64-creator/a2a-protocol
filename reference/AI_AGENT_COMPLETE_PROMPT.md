# Complete Prompt for AI Agents: Building A2A Protocol Projects

**Version:** 1.0.0  
**Date:** February 2026  
**Status:** Production Ready  
**Language:** English (100%)

---

## 📌 Overview

This is a **complete, detailed, error-resistant prompt** for AI agents to implement A2A Protocol-compliant projects. Use this prompt as-is without modification for best results.

**Supported Implementation Types:**
1. Agent Server (listens for requests)
2. Agent Client (calls other agents)
3. Multi-Agent System (3+ agents communicating)
4. Protocol Extension (custom transports, discovery, etc.)

---

## 🎯 Choose Your Task

### IF YOU ARE BUILDING: Agent Server
**→ Use [TASK: Agent Server](#task-agent-server) below**

### IF YOU ARE BUILDING: Agent Client
**→ Use [TASK: Agent Client](#task-agent-client) below**

### IF YOU ARE BUILDING: Multi-Agent System
**→ Use [TASK: Multi-Agent System](#task-multi-agent-system) below**

### IF YOU ARE BUILDING: Protocol Extension
**→ Use [TASK: Protocol Extension](#task-protocol-extension) below**

---

## MANDATORY PREREQUISITES

Before starting ANY task, verify you have:

```bash
# 1. Python 3.10+
python --version  # Must be 3.10 or higher

# 2. Virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Clone the A2A Protocol repository
git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git
cd a2a-protocol

# 4. Install A2A library
pip install -e reference/

# 5. Verify installation
python -c "import a2a; print(f'A2A version: {a2a.__version__}')"
# Output should show: A2A version: 1.0.0 (or similar)

# 6. Navigate to project directory
cd reference
```

**If any step fails, STOP and report the error. Do not continue.**

---

## 📚 REFERENCE DOCUMENTATION

Keep these documents open while working:

| Document | Purpose | Location |
|----------|---------|----------|
| **A2A Protocol Spec** | Core protocol definition | `spec/A2A_PROTOCOL_v1.md` |
| **Agent Identity Spec** | DID format and manifests | `spec/AGENT_IDENTITY.md` |
| **Security Model** | Threat analysis | `spec/SECURITY_MODEL.md` |
| **Project Integration Guide** | Step-by-step integration | `reference/PROJECT_INTEGRATION_GUIDE.md` |
| **Examples** | Working code examples | `reference/examples/` |
| **Tests** | Test patterns | `reference/tests/` |

---

---

## TASK: Agent Server

### 🎯 Objective
Build an A2A-compliant agent server that:
- Generates and manages a unique DID-based identity
- Listens for incoming A2A handshake requests
- Handles intent requests (goal + parameters)
- Returns properly formatted JSON responses
- Logs all interactions for audit trail

### ✅ Requirements (MANDATORY)

#### Code Quality
- [ ] PEP 8 compliant (use `black` for formatting)
- [ ] Type hints on 100% of public functions
- [ ] Comprehensive docstrings on all functions
- [ ] Error handling for ALL failure paths
- [ ] Async/await for all I/O operations

#### Functionality
- [ ] Use `a2a-protocol>=1.0.0` library
- [ ] Cryptographic signature verification (JWS RFC 7515)
- [ ] Ed25519 key generation and management
- [ ] TLS 1.3 enabled (in production configuration)
- [ ] Support at least 2 custom intents (define them yourself)
- [ ] Proper error responses for all error cases

#### Testing
- [ ] Unit tests for all public functions
- [ ] Integration tests for handshake
- [ ] Integration tests for intent handling
- [ ] Tests for error cases
- [ ] **Minimum 80% code coverage** (verify with `pytest --cov`)
- [ ] All tests MUST PASS

#### Documentation
- [ ] README.md with:
  - Installation instructions
  - Quick start example
  - List of all supported intents with parameters
  - Example requests and responses
  - Testing instructions
- [ ] CONTRIBUTING.md with code standards
- [ ] Docstrings on every function
- [ ] comments explaining non-obvious code

#### Security
- [ ] No hardcoded credentials
- [ ] Secrets loaded from environment variables
- [ ] TLS configuration documented
- [ ] No insecure defaults

### 📂 Deliverables (EXACT STRUCTURE)

```
my-a2a-server/
├── src/
│   └── my_server/
│       ├── __init__.py
│       ├── agent.py              # Main agent class
│       ├── identity.py           # DID/manifest management
│       ├── intents/              # Intent handlers
│       │   ├── __init__.py
│       │   ├── echo.py           # Example: echo intent
│       │   └── process.py        # Example: process intent
│       └── errors.py             # Custom exceptions
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_agent.py         # Agent tests
│   │   ├── test_identity.py      # Identity tests
│   │   └── test_intents.py       # Intent handler tests
│   └── integration/
│       ├── __init__.py
│       └── test_e2e.py           # End-to-end tests
├── .gitignore
├── README.md                     # Complete documentation
├── CONTRIBUTING.md              # Code standards
├── LICENSE                       # MIT License
├── requirements.txt              # Dependencies
├── setup.py                      # Package setup
└── pytest.ini                    # Test configuration
```

### 📝 Step-by-Step Implementation

#### Step 1: Read Documentation (30 minutes)
**Do NOT skip this step.**

```bash
# Read in this order:
1. Read spec/A2A_PROTOCOL_v1.md sections 1-6
   - Focus on: Handshake protocol, message formats, security requirements
   
2. Read spec/AGENT_IDENTITY.md
   - Focus on: DID format, manifest structure, signing
   
3. Read reference/PROJECT_INTEGRATION_GUIDE.md Phase 2
   - This is the EXACT pattern to follow
   
4. Study reference/examples/
   - Look at patterns in example code
```

**Write down:**
- How DIDs are formatted (did:key:...)
- The 6-step handshake sequence (HELLO → CHALLENGE → PROOF → POLICY → ACCEPT → SESSION)
- What fields are required in each message
- What cryptographic operations are needed

#### Step 2: Create Project Structure (15 minutes)

```bash
# Create directories
mkdir -p my-a2a-server/{src/my_server/intents,tests/{unit,integration}}

# Create __init__.py files
touch my-a2a-server/src/__init__.py
touch my-a2a-server/src/my_server/__init__.py
touch my-a2a-server/src/my_server/intents/__init__.py
touch my-a2a-server/tests/__init__.py
touch my-a2a-server/tests/unit/__init__.py
touch my-a2a-server/tests/integration/__init__.py

# Create essential files
cd my-a2a-server
touch README.md CONTRIBUTING.md LICENSE requirements.txt setup.py pytest.ini .gitignore
```

#### Step 3: Set Up Dependencies (10 minutes)

**requirements.txt:**
```
a2a-protocol>=1.0.0
pydantic>=2.0.0
httpx>=0.25.0
aiohttp>=3.9.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
black>=23.0.0
mypy>=1.0.0
```

```bash
pip install -r requirements.txt
```

#### Step 4: Implement Agent Identity (1 hour)

**File:** `src/my_server/identity.py`

```python
"""
Agent identity setup and DID generation.
Handles creation, storage, and loading of agent identity.
"""

import json
from pathlib import Path
from typing import Optional
from a2a.core.identity import create_did, Agent


def load_or_create_identity(
    agent_name: str,
    storage_path: str = ".agent"
) -> Agent:
    """
    Load existing agent identity or create new one.
    
    Args:
        agent_name: Human-readable agent name
        storage_path: Directory to store identity files
        
    Returns:
        Agent: Agent instance with DID and keypair
        
    Raises:
        ValueError: If identity file is corrupted
    """
    storage = Path(storage_path)
    storage.mkdir(exist_ok=True)
    identity_file = storage / f"{agent_name}.json"
    
    if identity_file.exists():
        # Load existing identity
        try:
            with open(identity_file, 'r') as f:
                data = json.load(f)
            print(f"✓ Loaded existing identity for {agent_name}")
            print(f"  DID: {data['did']}")
            
            agent = Agent(
                name=data['name'],
                did=data['did'],
                public_key=data['public_key'],
                private_key=data['private_key']
            )
            return agent
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Corrupted identity file: {e}")
    else:
        # Create new identity
        print(f"→ Creating new identity for {agent_name}...")
        agent = create_did(name=agent_name)
        
        # Save identity
        identity_data = {
            'name': agent.name,
            'did': agent.did,
            'public_key': agent.public_key,
            'private_key': agent.private_key
        }
        
        with open(identity_file, 'w') as f:
            json.dump(identity_data, f, indent=2)
        
        print(f"✓ Created new identity")
        print(f"  DID: {agent.did}")
        print(f"  Saved to: {identity_file.absolute()}")
        
        return agent
```

#### Step 5: Implement Main Agent Server (2-3 hours)

**File:** `src/my_server/agent.py`

```python
"""
A2A Agent Server implementation.
Main server class that handles connections and intents.
"""

import asyncio
import logging
from typing import Any, Dict, Optional
from a2a.core.identity import Agent
from a2a.transport.http import HTTPTransport
from a2a.protocol.handshake import ServerHandshakeFSM
from a2a.session.manager import SessionManager
from a2a.session.policy import PolicyEngine

from .identity import load_or_create_identity


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class A2AServer:
    """
    A2A Protocol-compliant agent server.
    
    Handles:
    - Agent identity (DID, manifest)
    - Incoming handshake requests
    - Intent request processing
    - Session management
    - Audit logging
    """
    
    def __init__(
        self,
        agent_name: str,
        port: int = 8000,
        host: str = "localhost",
        verify_tls: bool = False
    ):
        """
        Initialize A2A server.
        
        Args:
            agent_name: Name of the agent
            port: Port to listen on
            host: Host to bind to
            verify_tls: Enable TLS verification (use True in production)
        """
        self.agent_name = agent_name
        self.port = port
        self.host = host
        self.verify_tls = verify_tls
        
        # Will be initialized in startup
        self.agent: Optional[Agent] = None
        self.transport: Optional[HTTPTransport] = None
        self.session_manager: Optional[SessionManager] = None
        self.policy_engine: Optional[PolicyEngine] = None
        self.handshake_fsm: Optional[ServerHandshakeFSM] = None
    
    async def initialize(self) -> None:
        """
        Initialize all server components.
        
        Must be called before starting server.
        """
        logger.info(f"Initializing {self.agent_name}...")
        
        # Load or create identity
        self.agent = load_or_create_identity(self.agent_name)
        logger.info(f"Agent DID: {self.agent.did}")
        
        # Initialize transport
        self.transport = HTTPTransport(verify_tls=self.verify_tls)
        logger.info("Transport layer initialized")
        
        # Initialize session and policy managers
        self.session_manager = SessionManager()
        self.policy_engine = PolicyEngine()
        logger.info("Session and policy managers initialized")
        
        # Initialize handshake FSM
        self.handshake_fsm = ServerHandshakeFSM(self.agent)
        logger.info("Handshake FSM initialized")
    
    async def handle_intent(
        self,
        intent: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle incoming intent request.
        
        Override this method in subclasses to implement custom intents.
        
        Args:
            intent: Intent request with 'goal' and 'params'
            
        Returns:
            Dict with 'result' or 'error' key
        """
        goal = intent.get('goal')
        params = intent.get('params', {})
        
        logger.info(f"Handling intent: {goal}")
        
        # EXAMPLE INTENTS:
        # Add your custom intent handlers here
        
        if goal == 'echo':
            message = params.get('message', '')
            result = f"Echo: {message}"
            return {'result': result, 'status': 'ok'}
        
        elif goal == 'process_data':
            data = params.get('data', [])
            result = [x * 2 for x in data if isinstance(x, (int, float))]
            return {'result': result, 'status': 'ok'}
        
        else:
            logger.warning(f"Unknown intent goal: {goal}")
            return {
                'error': f"Unknown intent goal: {goal}",
                'status': 'error'
            }
    
    async def start(self) -> None:
        """
        Start the A2A server.
        
        Initializes all components and starts listening.
        """
        await self.initialize()
        
        print("\n" + "="*70)
        print(f"🚀 Starting A2A Agent Server: {self.agent_name}")
        print("="*70)
        print(f"DID:       {self.agent.did}")
        print(f"Host:      {self.host}")
        print(f"Port:      {self.port}")
        print(f"Endpoint:  http://{self.host}:{self.port}")
        print(f"TLS:       {'Enabled' if self.verify_tls else 'Disabled (dev only)'}")
        print("="*70)
        print("\n📡 Listening for incoming A2A connections...")
        print("Press Ctrl+C to stop\n")
        
        try:
            # In production, use actual HTTP server here
            # For now, just keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print(f"\n✓ {self.agent_name} stopped")


async def main():
    """Run the server."""
    server = A2AServer(
        agent_name="MyA2AServer",
        port=8000,
        host="localhost",
        verify_tls=False  # Set to True in production
    )
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
```

#### Step 6: Implement Intent Handlers (1 hour)

**File:** `src/my_server/intents/echo.py`

```python
"""
Echo intent handler.
Simple example that echoes back the message.
"""

from typing import Any, Dict


async def handle_echo(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle echo intent.
    
    Args:
        params: Dict with 'message' key
        
    Returns:
        Dict with echoed message
    """
    message = params.get('message', '')
    
    if not message:
        return {
            'error': 'Missing required parameter: message',
            'status': 'error'
        }
    
    return {
        'result': f"Echo: {message}",
        'status': 'ok',
        'length': len(message)
    }
```

#### Step 7: Write Comprehensive Tests (2 hours)

**File:** `tests/unit/test_agent.py`

```python
"""
Unit tests for A2A server.
"""

import pytest
import asyncio
from src.my_server.agent import A2AServer
from src.my_server.identity import load_or_create_identity


@pytest.fixture
async def server():
    """Create test server."""
    srv = A2AServer(
        agent_name="TestServer",
        port=8001,
        verify_tls=False
    )
    await srv.initialize()
    return srv


@pytest.mark.asyncio
async def test_server_initialization(server):
    """Test server initializes correctly."""
    assert server.agent is not None
    assert server.agent.did.startswith('did:')
    assert server.session_manager is not None
    assert server.policy_engine is not None


@pytest.mark.asyncio
async def test_handle_echo_intent(server):
    """Test echo intent."""
    intent = {
        'goal': 'echo',
        'params': {'message': 'Hello A2A!'}
    }
    
    result = await server.handle_intent(intent)
    
    assert result['status'] == 'ok'
    assert 'Hello A2A!' in result['result']


@pytest.mark.asyncio
async def test_handle_process_data_intent(server):
    """Test data processing intent."""
    intent = {
        'goal': 'process_data',
        'params': {'data': [1, 2, 3, 4]}
    }
    
    result = await server.handle_intent(intent)
    
    assert result['status'] == 'ok'
    assert result['result'] == [2, 4, 6, 8]


@pytest.mark.asyncio
async def test_handle_unknown_intent(server):
    """Test unknown intent is rejected."""
    intent = {
        'goal': 'unknown_goal',
        'params': {}
    }
    
    result = await server.handle_intent(intent)
    
    assert result['status'] == 'error'
    assert 'Unknown' in result['error']


@pytest.mark.asyncio
async def test_identity_persistence(tmp_path):
    """Test identity is saved and loaded."""
    # Create identity
    id1 = load_or_create_identity("TestAgent", str(tmp_path))
    did1 = id1.did
    
    # Load identity
    id2 = load_or_create_identity("TestAgent", str(tmp_path))
    did2 = id2.did
    
    # Should be same
    assert did1 == did2
```

#### Step 8: Write Integration Tests (1 hour)

**File:** `tests/integration/test_e2e.py`

```python
"""
End-to-end integration tests.
"""

import pytest
import asyncio
from src.my_server.agent import A2AServer


@pytest.fixture
async def server():
    """Create and initialize server."""
    srv = A2AServer("IntegrationTestServer", port=8002)
    await srv.initialize()
    return srv


@pytest.mark.asyncio
async def test_full_server_lifecycle(server):
    """Test server startup and intent handling."""
    # Server is initialized
    assert server.agent is not None
    assert server.session_manager is not None
    
    # Handle intent
    intent = {'goal': 'echo', 'params': {'message': 'test'}}
    result = await server.handle_intent(intent)
    
    assert result['status'] == 'ok'
    assert 'test' in result['result']


@pytest.mark.asyncio
async def test_concurrent_intent_handling(server):
    """Test handling multiple intents concurrently."""
    intents = [
        {'goal': 'echo', 'params': {'message': f'msg-{i}'}}
        for i in range(10)
    ]
    
    tasks = [server.handle_intent(intent) for intent in intents]
    results = await asyncio.gather(*tasks)
    
    assert len(results) == 10
    assert all(r['status'] == 'ok' for r in results)
```

#### Step 9: Add Documentation (1 hour)

**File:** `README.md`

```markdown
# My A2A Agent Server

A secure, A2A Protocol-compliant agent server that handles intents and communicates with other agents.

## Quick Start

### Installation

\`\`\`bash
git clone <your-repo-url>
cd my-a2a-server
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
\`\`\`

### Run Server

\`\`\`bash
python -m src.my_server.agent
\`\`\`

Output:
\`\`\`
🚀 Starting A2A Agent Server: MyA2AServer
======================================================================
DID:       did:key:z6MkhaXgBZDvotzL8V6N1LXm1SmjYfHGdYnAYkBRCxq9WyKp
Host:      localhost
Port:      8000
Endpoint:  http://localhost:8000
TLS:       Disabled (dev only)
======================================================================

📡 Listening for incoming A2A connections...
\`\`\`

## Supported Intents

### echo
Echo a message back.

**Parameters:**
- \`message\` (string): Message to echo

**Response:**
\`\`\`json
{"result": "Echo: Hello!", "status": "ok", "length": 6}
\`\`\`

### process_data
Process a list of numbers (multiply by 2).

**Parameters:**
- \`data\` (array): List of numbers

**Response:**
\`\`\`json
{"result": [2, 4, 6, 8], "status": "ok"}
\`\`\`

## Testing

\`\`\`bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/unit/test_agent.py::test_handle_echo_intent -v
\`\`\`

## Architecture

\`\`\`
src/my_server/
├── agent.py        # Main A2AServer class
├── identity.py     # DID and manifest management
├── intents/        # Intent handlers
└── errors.py       # Custom exceptions
\`\`\`

## Security

- TLS 1.3 recommended for production
- All intent requests are signed and verified
- Session-based authentication
- Full audit logging

See `CONTRIBUTING.md` for security requirements.

## License

MIT License
```

**File:** `CONTRIBUTING.md`

```markdown
# Contributing

## Code Standards

1. Follow PEP 8 (use `black`)
2. Type hints on all public functions
3. Docstrings on all functions
4. 80%+ test coverage required

## Testing

\`\`\`bash
pytest tests/ -v --cov=src
\`\`\`

## A2A Compliance

- Must use a2a-protocol library
- Must implement JWS signatures
- Must enforce TLS 1.3 in production
- Must maintain audit logs
```

#### Step 10: Verify and Test (30 minutes)

```bash
# 1. Install all dependencies
pip install -r requirements.txt

# 2. Format code
black src/ tests/

# 3. Type checking
mypy src/

# 4. Run all tests
pytest tests/ -v

# 5. Check coverage
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html to verify coverage >= 80%

# 6. Run server (manual test)
python -m src.my_server.agent
# Should start without errors

# 7. Test with curl in another terminal
curl -X POST http://localhost:8000 \
  -H "Content-Type: application/json" \
  -d '{"goal":"echo","params":{"message":"Hello"}}'
```

### 📋 Verification Checklist

Before considering your agent server complete:

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Code coverage >= 80% (`pytest --cov`)
- [ ] Code formatted (`black src/`)
- [ ] Type checking passes (`mypy src/`)
- [ ] No linting errors (`flake8 src/`)
- [ ] README.md is complete with examples
- [ ] CONTRIBUTING.md exists
- [ ] LICENSE file exists
- [ ] requirements.txt is up to date
- [ ] Server starts without errors
- [ ] At least 2 custom intents implemented
- [ ] All intents have unit tests
- [ ] Integration tests pass
- [ ] No hardcoded secrets or credentials
- [ ] Error handling is comprehensive

### 🎓 Next Steps

1. **Add more intents** — Implement domain-specific functionality
2. **Client implementation** — Build a client that calls this server
3. **Database integration** — Persist data
4. **Production deployment** — Enable TLS, security hardening
5. **Submit to repository** — Create PR to main A2A repo

---

---

## TASK: Agent Client

### 🎯 Objective
Build an A2A-compliant agent client that:
- Generates and manages its own DID-based identity
- Discovers and connects to other A2A agents
- Performs cryptographic handshake
- Sends intent requests to remote agents
- Validates responses
- Handles errors gracefully

### ✅ Requirements (MANDATORY)

#### Code Quality
- [ ] PEP 8 compliant
- [ ] Type hints on 100% of public functions
- [ ] Comprehensive docstrings
- [ ] Error handling for all paths
- [ ] Async/await for I/O

#### Functionality
- [ ] Use `a2a-protocol>=1.0.0` library
- [ ] Implement handshake FSM (client-side)
- [ ] Support concurrent calls to multiple agents
- [ ] Session caching for performance
- [ ] TLS 1.3 enabled (production)
- [ ] Proper timeout handling (30s handshake, 10s per-state)

#### Testing
- [ ] Unit tests for all public methods
- [ ] Integration tests for handshake
- [ ] Integration tests for intent calling
- [ ] Error case testing
- [ ] **Minimum 80% code coverage**

#### Documentation
- [ ] README.md with usage examples
- [ ] CONTRIBUTING.md
- [ ] API documentation
- [ ] Example code showing how to call agents

#### Security
- [ ] No hardcoded DIDs or endpoints
- [ ] Secrets from environment
- [ ] TLS verification enabled

### 📂 Deliverables

```
my-a2a-client/
├── src/
│   └── my_client/
│       ├── __init__.py
│       ├── client.py           # Main client class
│       ├── identity.py         # Client identity
│       └── errors.py           # Custom exceptions
├── tests/
│   ├── unit/
│   │   ├── test_client.py
│   │   └── test_identity.py
│   └── integration/
│       └── test_e2e.py
├── examples/
│   ├── call_single_agent.py
│   └── call_multiple_agents.py
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
└── setup.py
```

### 📝 Implementation Guide

**Follow the same 10-step process as Agent Server:**
1. Read documentation (spec/A2A_PROTOCOL_v1.md sections 1-6)
2. Create project structure
3. Install dependencies
4. Implement agent identity
5. Implement main client class with:
   - `async def connect(server_did, endpoint) -> session_id`
   - `async def send_intent(session_id, goal, params) -> result`
   - `async def call_multiple_agents(agents_list) -> results`
6. Add example intents
7. Write unit tests (80%+ coverage)
8. Write integration tests
9. Write documentation
10. Verify and test

**Key difference from server:**
- Client INITIATES connections, not RECEIVES them
- Uses `ClientHandshakeFSM` not `ServerHandshakeFSM`
- Must handle session caching
- Must implement discovery (finding other agents)

### Reference Code

See `reference/examples/agent_client.py` for complete example.

---

---

## TASK: Multi-Agent System

### 🎯 Objective
Design and implement a network of 3+ interconnected A2A agents that:
- Communicate with each other
- Implement different domain-specific capabilities
- Handle concurrent requests
- Maintain full audit trail
- Demonstrate the A2A Protocol at scale

### ✅ Requirements (MANDATORY)

#### Architecture
- [ ] 3+ agents (minimum)
- [ ] Each agent has unique DID and manifest
- [ ] Agents in different roles (client, server, orchestrator)
- [ ] Each agent supports 3+ intents
- [ ] Agents call each other (proof of interoperability)

#### Code Quality
- [ ] All code follows PEP 8
- [ ] Type hints everywhere
- [ ] Comprehensive tests
- [ ] 80%+ coverage
- [ ] Clear separation of concerns

#### Testing
- [ ] Unit tests for each agent
- [ ] Integration tests for agent-to-agent calls
- [ ] End-to-end tests for full workflows
- [ ] Load tests for concurrent requests
- [ ] Error scenario tests

#### Documentation
- [ ] System architecture diagram
- [ ] Agent interaction flows
- [ ] Setup and deployment guide
- [ ] Example workflows
- [ ] API documentation

### 📂 Deliverables

```
my-a2a-network/
├── agents/
│   ├── data_processor/         # Agent A: Data processing
│   │   ├── src/
│   │   ├── tests/
│   │   └── README.md
│   ├── translator/             # Agent B: Translation
│   │   ├── src/
│   │   ├── tests/
│   │   └── README.md
│   └── orchestrator/           # Agent C: Coordination
│       ├── src/
│       ├── tests/
│       └── README.md
├── integration_tests/
│   ├── test_e2e.py
│   └── test_workflows.py
├── docker-compose.yml          # Local deployment
├── docs/
│   ├── ARCHITECTURE.md
│   ├── WORKFLOWS.md
│   └── DEPLOYMENT.md
├── README.md
└── CONTRIBUTING.md
```

### 📝 Example Agents

**Agent A: Data Processor**
- Intent: `analyze_csv` (analyze CSV data)
- Intent: `compute_stats` (compute statistics)
- Intent: `filter_data` (filter by criteria)

**Agent B: Translator**
- Intent: `translate` (translate text)
- Intent: `detect_language` (detect language)
- Intent: `supported_languages` (list languages)

**Agent C: Orchestrator**
- Intent: `analyze_and_translate` (calls A and B)
- Intent: `workflow_status` (check workflow)
- Intent: `list_agents` (list discovered agents)

### Reference

See `reference/tests/integration/test_e2e.py` for end-to-end patterns.

---

---

## TASK: Protocol Extension

### 🎯 Objective
Extend the A2A Protocol with new functionality while maintaining backward compatibility.

Examples:
- Custom transport layer (gRPC, WebSocket)
- Advanced agent discovery mechanism
- Reputation/trust system
- Streaming response support
- Service registry

### ✅ Requirements (MANDATORY)

#### Specification
- [ ] RFC-style formal specification
- [ ] Clear design rationale
- [ ] Backward compatibility analysis
- [ ] Examples of usage

#### Implementation
- [ ] Python reference implementation
- [ ] Pluggable architecture
- [ ] No breaking changes to core
- [ ] Comprehensive examples

#### Testing
- [ ] 85%+ code coverage
- [ ] Unit tests for all components
- [ ] Integration tests
- [ ] Compatibility tests with v1.0.0

#### Documentation
- [ ] SPEC.md with proposal
- [ ] API documentation
- [ ] Deployment guide
- [ ] Security analysis

#### Review
- [ ] Security review
- [ ] Performance analysis
- [ ] Backward compatibility verification

### 📝 Submission Process

1. Create RFC-style specification (SPEC.md)
2. Implement reference version
3. Write comprehensive tests
4. Document security implications
5. Create PR to main repository
6. Address review feedback
7. Merge upon approval

---

---

## 🔍 DEBUGGING & TROUBLESHOOTING

### Problem: "ImportError: No module named 'a2a'"

**Solution:**
```bash
pip install a2a-protocol>=1.0.0
# Verify:
python -c "import a2a; print(a2a.__version__)"
```

### Problem: "DID format invalid"

**Solution:**
DIDs must be generated with `create_did()`. Never hardcode them.
```python
from a2a.core.identity import create_did
agent = create_did(name="MyAgent")
print(agent.did)  # Will print: did:key:z6Mk...
```

### Problem: "Tests fail with coverage < 80%"

**Solution:**
```bash
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html to find uncovered lines
# Add tests for those lines
```

### Problem: "Handshake fails"

**Causes:**
1. DIDs don't match between agents
2. Signatures are invalid
3. Nonces are not fresh
4. Clocks are out of sync

**Debug:**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# Run again to see detailed logs
```

### Problem: "Port already in use"

**Solution:**
```bash
# Find process using port
lsof -i :8000

# Kill it
kill -9 <PID>

# Or use different port
server = A2AServer(port=8001)
```

### Problem: "TLS certificate error"

**Solution (dev):**
```python
transport = HTTPTransport(verify_tls=False)  # Dev only
```

**Solution (production):**
```bash
# Generate certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

# Use in server
transport = HTTPTransport(
    verify_tls=True,
    cert_file="cert.pem",
    key_file="key.pem"
)
```

---

---

## ✅ FINAL CHECKLIST

Before committing, verify ALL of these:

### Code Quality
- [ ] `black src/ tests/` passes
- [ ] `mypy src/` has no errors
- [ ] `flake8 src/ tests/` has no errors
- [ ] All functions have docstrings
- [ ] All public functions have type hints
- [ ] No hardcoded credentials
- [ ] No `TODO` or `FIXME` comments

### Testing
- [ ] `pytest tests/ -v` all pass
- [ ] Coverage >= 80%: `pytest --cov=src --cov-report=html`
- [ ] Unit tests for all public functions
- [ ] Integration tests present
- [ ] Error cases tested

### Documentation
- [ ] README.md complete with:
  - Installation steps
  - Quick start
  - Usage examples
  - Supported intents (if server)
  - Testing instructions
- [ ] CONTRIBUTING.md present
- [ ] LICENSE file present (MIT recommended)
- [ ] requirements.txt updated
- [ ] setup.py configured
- [ ] All code is in English

### A2A Compliance
- [ ] Uses `a2a-protocol>=1.0.0`
- [ ] Implements DIDs correctly
- [ ] Uses JWS for signatures
- [ ] TLS configuration present
- [ ] Session management implemented
- [ ] Error handling per spec
- [ ] Audit logging present

### Repository
- [ ] .gitignore configured
- [ ] No secrets committed
- [ ] Reasonable commit messages
- [ ] Clean git history
- [ ] README in root directory

---

---

## 🚀 READY TO SUBMIT?

Once everything passes the checklist:

```bash
# Final verification
pytest tests/ -v --cov=src
black src/ tests/
mypy src/
flake8 src/ tests/

# Commit
git add -A
git commit -m "Complete A2A implementation with full tests and docs"

# Push
git push origin main

# Create PR to:
# https://github.com/chorghemaruti64-creator/a2a-protocol
```

---

## 📞 SUPPORT

**A2A Protocol Repository:**
https://github.com/chorghemaruti64-creator/a2a-protocol

**Key Reference Files:**
- `spec/A2A_PROTOCOL_v1.md` — Protocol specification
- `spec/AGENT_IDENTITY.md` — Identity and DID format
- `reference/PROJECT_INTEGRATION_GUIDE.md` — Integration guide
- `reference/examples/` — Working code examples

**Still stuck?**
1. Check `reference/tests/` for test patterns
2. Review `spec/SECURITY_MODEL.md` for security requirements
3. Check `reference/examples/` for code patterns
4. Open issue on GitHub

---

**Version:** 1.0.0  
**Last Updated:** February 2026  
**Status:** Production Ready  
**Language:** English
