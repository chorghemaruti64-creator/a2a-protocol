# Project Integration Guide for A2A Protocol

## Complete Guideline: Adding Your Project to the A2A Agent Ecosystem

This document provides step-by-step instructions for integrating your project with the A2A Protocol, enabling your agents to communicate securely within the A2A network.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [What Counts as a Project](#what-counts-as-a-project)
3. [Step-by-Step Integration Guide](#step-by-step-integration-guide)
4. [Project Structure Requirements](#project-structure-requirements)
5. [Testing Requirements](#testing-requirements)
6. [Documentation Requirements](#documentation-requirements)
7. [Integration Checklist](#integration-checklist)
8. [Submission and Review Process](#submission-and-review-process)
9. [Complete Examples](#complete-examples)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before integrating your project with A2A, ensure you have:

### System Requirements
- **Python 3.10+** (A2A requires Python 3.10 or higher)
- **Git** for version control
- **Virtual Environment** tool (venv, virtualenv, or poetry)
- **pip** package manager

### Knowledge Requirements
- Basic understanding of Python asyncio
- Familiarity with REST APIs / JSON-RPC 2.0
- Understanding of cryptographic concepts (DIDs, signatures)
- Read the A2A Protocol specification

### Software Dependencies
```bash
# Core A2A dependencies
cryptography>=41.0.0       # Cryptographic operations
pydantic>=2.0.0            # Data validation
httpx>=0.25.0              # Async HTTP client
aiohttp>=3.9.0             # Async HTTP server

# Testing
pytest>=7.0.0              # Test framework
pytest-asyncio>=0.21.0     # Async test support

# Development (optional)
black>=23.0.0              # Code formatting
mypy>=1.0.0                # Type checking
flake8>=6.0.0              # Linting
```

### Required Credentials
- A2A Agent Identity (DID and keypair) — auto-generated
- TLS certificate for HTTPS endpoints (in production)
- Optional: GitHub account for contributing

---

## What Counts as a Project?

In the A2A ecosystem, a **project** is any software that:

### ✅ Valid Projects

1. **Agent Service** — Autonomous service that responds to intent requests
   - Example: Document analyzer, translation service, data processor
   - Must: Expose A2A endpoint, handle intents, return results

2. **Agent Client** — Application that calls other agents
   - Example: Orchestrator, task runner, workflow engine
   - Must: Implement A2A handshake, send properly formatted intents

3. **Specialized Agent** — Domain-specific agent (legal, medical, financial)
   - Example: Contract analyzer, medical data query, stock analyst
   - Must: Implement security policies, follow domain standards

4. **Agent Network** — Multiple agents collaborating
   - Example: Multi-agent system, federated service
   - Must: Demonstrate agent-to-agent communication

5. **Protocol Extension** — Enhancement to A2A specification
   - Example: New transport layer, discovery mechanism, policy engine
   - Must: Follow RFC process, include formal spec, reference implementation

### ❌ Invalid Projects

- ❌ Non-agent software (regular web services without A2A)
- ❌ Incomplete implementations (no tests, no docs)
- ❌ Proprietary/closed code
- ❌ Projects without proper security review

---

## Step-by-Step Integration Guide

### Phase 1: Preparation (30 minutes)

#### Step 1.1: Create Project Repository

```bash
# Create your project directory
mkdir my-a2a-project
cd my-a2a-project

# Initialize Git
git init
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### Step 1.2: Set Up Project Structure

```bash
# Create standard directories
mkdir -p src/my_project
mkdir -p tests/unit tests/integration
mkdir -p docs examples
mkdir -p config

# Create essential files
touch README.md
touch CONTRIBUTING.md
touch LICENSE
touch requirements.txt
touch .gitignore
touch setup.py
```

#### Step 1.3: Install A2A Framework

```bash
# Install from PyPI (when released)
pip install a2a-protocol>=1.0.0

# OR: Install from local reference implementation
pip install -e /path/to/a2a-protocol/reference

# Verify installation
python -c "import a2a; print(f'A2A version: {a2a.__version__}')"
```

---

### Phase 2: Implementation (2-4 hours)

#### Step 2.1: Create Agent Identity

Every agent needs a unique identity. Create `config/identity.py`:

```python
"""
Agent identity setup and DID generation.
"""
from a2a.core.identity import create_did, Agent
from pathlib import Path
import json

def load_or_create_identity(agent_name: str, storage_path: str = ".agent"):
    """
    Load existing agent identity or create new one.
    
    Args:
        agent_name: Human-readable name for agent
        storage_path: Directory to store identity
        
    Returns:
        Agent: Agent instance with DID and keypair
    """
    storage = Path(storage_path)
    storage.mkdir(exist_ok=True)
    identity_file = storage / f"{agent_name}.json"
    
    if identity_file.exists():
        # Load existing identity
        with open(identity_file, 'r') as f:
            data = json.load(f)
        print(f"✓ Loaded existing identity for {agent_name}")
        # Reconstruct Agent object
        agent = Agent(
            name=data['name'],
            did=data['did'],
            public_key=data['public_key'],
            private_key=data['private_key']
        )
    else:
        # Create new identity
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
        print(f"✓ Created new identity for {agent_name}")
        print(f"  DID: {agent.did}")
    
    return agent

# Usage
if __name__ == "__main__":
    my_agent = load_or_create_identity("MyServiceAgent")
    print(f"Agent: {my_agent.name}")
    print(f"DID: {my_agent.did}")
```

#### Step 2.2: Implement Agent Server

Create `src/my_project/agent_server.py`:

```python
"""
A2A Agent Server implementation.
Receives intent requests and returns results.
"""
import asyncio
from typing import Any, Dict
from a2a.core.identity import Agent
from a2a.transport.http import HTTPTransport
from a2a.protocol.handshake import ServerHandshakeFSM
from a2a.session.manager import SessionManager
from a2a.session.policy import PolicyEngine
from config.identity import load_or_create_identity

class MyAgent:
    """
    Example agent service that handles intents.
    """
    
    def __init__(self, name: str, port: int = 8000):
        self.agent = load_or_create_identity(name)
        self.port = port
        self.transport = None
        self.session_manager = SessionManager()
        self.policy_engine = PolicyEngine()
        self.handshake_fsm = None
        
    async def initialize(self):
        """Initialize agent components."""
        self.transport = HTTPTransport(verify_tls=False)  # Use TLS in production
        self.handshake_fsm = ServerHandshakeFSM(self.agent)
        print(f"✓ {self.agent.name} initialized")
        print(f"  DID: {self.agent.did}")
        
    async def handle_intent(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming intent request.
        
        Override this method to implement your agent's logic.
        
        Args:
            intent: Intent request with 'goal' and 'params'
            
        Returns:
            Dict with 'result' or 'error'
        """
        goal = intent.get('goal')
        params = intent.get('params', {})
        
        if goal == 'echo':
            # Simple echo example
            return {'result': f"Echo: {params.get('message', '')}", 'status': 'ok'}
        
        elif goal == 'process_data':
            # Example: Process data
            data = params.get('data', [])
            result = [x * 2 for x in data]  # Simple processing
            return {'result': result, 'status': 'ok'}
        
        else:
            return {'error': f"Unknown goal: {goal}", 'status': 'error'}
    
    async def start_server(self):
        """Start listening for incoming connections."""
        await self.initialize()
        
        print(f"\n{'='*60}")
        print(f"Starting {self.agent.name}")
        print(f"{'='*60}")
        print(f"Listening on: http://localhost:{self.port}")
        print(f"Agent DID: {self.agent.did}")
        print(f"\nWaiting for incoming connections...")
        print(f"Press Ctrl+C to stop\n")
        
        # Start HTTP server (simplified example)
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print(f"\n✓ {self.agent.name} stopped")

# Usage
async def main():
    agent = MyAgent(name="ServiceAgent", port=8000)
    await agent.start_server()

if __name__ == "__main__":
    asyncio.run(main())
```

#### Step 2.3: Implement Agent Client

Create `src/my_project/agent_client.py`:

```python
"""
A2A Agent Client implementation.
Calls other agents with A2A protocol.
"""
import asyncio
from a2a.core.identity import Agent
from a2a.transport.http import HTTPTransport
from a2a.protocol.handshake import ClientHandshakeFSM
from config.identity import load_or_create_identity

class AgentClient:
    """
    Client for calling other A2A agents.
    """
    
    def __init__(self, agent_name: str):
        self.agent = load_or_create_identity(agent_name)
        self.transport = HTTPTransport(verify_tls=False)
        self.sessions = {}  # Cache sessions per server
        
    async def initialize(self):
        """Initialize client."""
        print(f"✓ Client {self.agent.name} initialized")
        print(f"  DID: {self.agent.did}")
        
    async def call_agent(
        self,
        server_did: str,
        server_endpoint: str,
        goal: str,
        params: dict = None
    ) -> dict:
        """
        Call another agent with an intent.
        
        Args:
            server_did: DID of target agent
            server_endpoint: HTTP endpoint (e.g., http://localhost:8000)
            goal: Intent goal (e.g., 'echo', 'process_data')
            params: Intent parameters (default: {})
            
        Returns:
            Result from target agent
        """
        if params is None:
            params = {}
        
        try:
            # Step 1: Establish handshake with server
            print(f"\n→ Calling {server_did}")
            print(f"  Goal: {goal}")
            
            client_fsm = ClientHandshakeFSM(self.agent, server_did)
            session_id, expires_at = await client_fsm.handshake(
                self.transport,
                server_endpoint
            )
            
            print(f"  ✓ Session established: {session_id}")
            
            # Step 2: Send intent request
            intent_request = {
                'jsonrpc': '2.0',
                'method': 'send_intent',
                'params': {
                    'goal': goal,
                    'params': params,
                    'session_id': session_id
                },
                'id': 'req-001'
            }
            
            # Step 3: Receive and process result
            response = await self.transport.send(
                server_endpoint + '/a2a',
                intent_request
            )
            
            print(f"  ✓ Response: {response}")
            
            # Step 4: Close session
            # (In production, implement proper session cleanup)
            
            return response
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return {'error': str(e), 'status': 'failed'}
    
    async def batch_call(self, agents: list) -> dict:
        """
        Call multiple agents concurrently.
        
        Args:
            agents: List of (server_did, endpoint, goal, params) tuples
            
        Returns:
            Dict with results for each agent
        """
        tasks = [
            self.call_agent(did, endpoint, goal, params)
            for did, endpoint, goal, params in agents
        ]
        results = await asyncio.gather(*tasks)
        return {'results': results}

# Usage
async def main():
    client = AgentClient(agent_name="ClientAgent")
    await client.initialize()
    
    # Call a server agent
    result = await client.call_agent(
        server_did="did:key:z6MkhaXgBZDvotzL8V6N1LXm1SmjYfHGdYnAYkBRCxq9WyKp",
        server_endpoint="http://localhost:8000",
        goal="echo",
        params={"message": "Hello from A2A!"}
    )
    
    print(f"\nFinal Result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

### Phase 3: Testing (1-2 hours)

#### Step 3.1: Create Unit Tests

Create `tests/unit/test_agent.py`:

```python
"""
Unit tests for agent functionality.
"""
import pytest
import asyncio
from src.my_project.agent_server import MyAgent
from src.my_project.agent_client import AgentClient

@pytest.fixture
async def agent():
    """Create test agent."""
    agent = MyAgent(name="TestAgent", port=8001)
    await agent.initialize()
    return agent

@pytest.fixture
async def client():
    """Create test client."""
    client = AgentClient(agent_name="TestClient")
    await client.initialize()
    return client

@pytest.mark.asyncio
async def test_agent_initialization(agent):
    """Test agent initializes correctly."""
    assert agent.agent is not None
    assert agent.agent.did.startswith('did:')
    print(f"✓ Agent DID: {agent.agent.did}")

@pytest.mark.asyncio
async def test_handle_echo_intent(agent):
    """Test echo intent handling."""
    intent = {
        'goal': 'echo',
        'params': {'message': 'test message'}
    }
    result = await agent.handle_intent(intent)
    
    assert result['status'] == 'ok'
    assert 'test message' in result['result']

@pytest.mark.asyncio
async def test_handle_unknown_intent(agent):
    """Test unknown intent rejection."""
    intent = {
        'goal': 'unknown_goal',
        'params': {}
    }
    result = await agent.handle_intent(intent)
    
    assert result['status'] == 'error'
    assert 'Unknown' in result['error']

@pytest.mark.asyncio
async def test_client_initialization(client):
    """Test client initializes correctly."""
    assert client.agent is not None
    assert client.agent.did.startswith('did:')
```

#### Step 3.2: Run Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest tests/ -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_agent.py -v
```

---

### Phase 4: Documentation (1 hour)

#### Step 4.1: Write README.md

```markdown
# My A2A Project

**Description:** Brief description of what your agent does.

**Version:** 1.0.0  
**Status:** Production Ready  
**License:** MIT  

## Quick Start

### Installation

\`\`\`bash
pip install -r requirements.txt
\`\`\`

### Run Agent Server

\`\`\`bash
python -m src.my_project.agent_server
\`\`\`

Output:
\`\`\`
✓ ServiceAgent initialized
  DID: did:key:z6MkhaXgBZDvotzL8V6N1LXm1SmjYfHGdYnAYkBRCxq9WyKp

Listening on: http://localhost:8000
\`\`\`

### Call from Another Agent

\`\`\`python
import asyncio
from src.my_project.agent_client import AgentClient

async def main():
    client = AgentClient("ClientAgent")
    result = await client.call_agent(
        server_did="did:key:z6MkhaXgBZDvotzL8V6N1LXm1SmjYfHGdYnAYkBRCxq9WyKp",
        server_endpoint="http://localhost:8000",
        goal="echo",
        params={"message": "Hello!"}
    )
    print(result)

asyncio.run(main())
\`\`\`

## Supported Intents

### echo
Echo a message back.

**Parameters:**
- `message` (string): Message to echo

**Response:**
\`\`\`json
{"result": "Echo: Hello!", "status": "ok"}
\`\`\`

### process_data
Process a list of numbers.

**Parameters:**
- `data` (array): List of numbers

**Response:**
\`\`\`json
{"result": [2, 4, 6, 8], "status": "ok"}
\`\`\`

## Testing

\`\`\`bash
pytest tests/ -v --cov=src
\`\`\`

## Contributing

See CONTRIBUTING.md

## License

MIT License
```

#### Step 4.2: Write CONTRIBUTING.md

```markdown
# Contributing to My A2A Project

## Code Standards

1. Follow PEP 8 style guide
2. Add docstrings to all functions
3. Write tests for new functionality
4. Maintain 80%+ test coverage

## Pull Request Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes and add tests
4. Ensure all tests pass: `pytest tests/ -v`
5. Submit PR with description

## A2A Protocol Compliance

All changes must comply with:
- A2A Protocol v1.0.0 specification
- TLS 1.3 requirement
- Signature verification requirements
- Audit logging requirements
```

---

## Project Structure Requirements

Your project must have the following structure:

```
my-a2a-project/
├── src/
│   └── my_project/
│       ├── __init__.py
│       ├── agent_server.py      # Server implementation
│       ├── agent_client.py       # Client implementation
│       └── intents/              # Intent handlers
│           ├── __init__.py
│           ├── echo.py
│           └── process_data.py
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   └── test_agent.py
│   └── integration/
│       ├── __init__.py
│       └── test_e2e.py
├── config/
│   ├── __init__.py
│   ├── identity.py              # Agent identity setup
│   └── policy.py                # Security policies
├── examples/
│   ├── simple_client.py
│   └── multi_agent.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── DEPLOYMENT.md
├── .agent/                      # (Auto-created) Agent identities
├── .gitignore
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
├── setup.py
└── pytest.ini
```

---

## Testing Requirements

### Minimum Requirements

✅ **80% code coverage** on critical paths
✅ **Unit tests** for all public functions
✅ **Integration tests** for agent communication
✅ **Security tests** for authentication and policies
✅ **Error handling tests** for all edge cases

### Test Execution Checklist

```bash
# 1. Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# 2. Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=html

# 3. Verify coverage is >= 80%
# Open htmlcov/index.html to check

# 4. Run linting
pip install flake8
flake8 src/ --max-line-length=100

# 5. Type checking
pip install mypy
mypy src/

# 6. Security scanning
pip install bandit
bandit -r src/
```

### Test Output Example

```
tests/unit/test_agent.py::test_agent_initialization PASSED
tests/unit/test_agent.py::test_handle_echo_intent PASSED
tests/unit/test_agent.py::test_handle_unknown_intent PASSED
tests/integration/test_e2e.py::test_agent_to_agent_call PASSED

======================== 4 passed in 1.23s ========================
Coverage: 87% (critical paths)
```

---

## Documentation Requirements

Every project must include:

### 1. README.md
- **What:** Quick description, quick start, usage examples
- **Length:** 3-5 sections
- **Must include:**
  - Installation instructions
  - Quick start example
  - List of supported intents
  - Testing instructions

### 2. CONTRIBUTING.md
- **What:** How others can contribute
- **Must include:**
  - Code standards
  - Pull request process
  - A2A compliance requirements

### 3. License (MIT recommended)
```
MIT License

Copyright (c) 2026 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

### 4. requirements.txt
```
a2a-protocol>=1.0.0
pydantic>=2.0.0
httpx>=0.25.0
aiohttp>=3.9.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
```

### 5. Optional but Recommended
- `ARCHITECTURE.md` — System design
- `DEPLOYMENT.md` — Production setup
- `API.md` — Complete API reference

---

## Integration Checklist

Use this checklist to verify your project is ready for submission:

### Code Quality ✅
- [ ] Code follows PEP 8 style guide
- [ ] All functions have docstrings
- [ ] No `TODO` or `FIXME` comments (or all resolved)
- [ ] Type hints on 100% of public functions
- [ ] Linting passes (`flake8`)
- [ ] Type checking passes (`mypy`)
- [ ] Security scan passes (`bandit`)

### Testing ✅
- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Code coverage >= 80% (verify with `--cov-report=html`)
- [ ] Unit tests for all public functions
- [ ] Integration tests for agent communication
- [ ] Error paths tested
- [ ] Concurrent operations tested

### A2A Protocol Compliance ✅
- [ ] Uses A2A identity (DIDs)
- [ ] Implements proper handshake
- [ ] Uses TLS 1.3 (or documented as TODO)
- [ ] Signs all messages (JWS)
- [ ] Implements session management
- [ ] Enforces security policies
- [ ] Logs all interactions (audit log)
- [ ] Handles errors per spec

### Documentation ✅
- [ ] README.md complete with examples
- [ ] CONTRIBUTING.md present
- [ ] License file present (MIT recommended)
- [ ] requirements.txt up to date
- [ ] All code is in English
- [ ] API documentation complete
- [ ] No spelling errors

### Repository ✅
- [ ] Git history clean (logical commits)
- [ ] .gitignore configured
- [ ] No secrets in repository
- [ ] README in root directory
- [ ] License file in root directory

### Security ✅
- [ ] No hardcoded credentials
- [ ] No insecure defaults
- [ ] TLS verification enabled (production)
- [ ] Secrets loaded from environment
- [ ] Security practices documented in CONTRIBUTING.md

---

## Submission and Review Process

### Step 1: Prepare Your Project

```bash
# Ensure everything is ready
pytest tests/ -v --cov=src
flake8 src/
mypy src/
bandit -r src/

# Commit all changes
git add .
git commit -m "Project ready for submission"

# Create GitHub repository
# Push to GitHub
git push origin main
```

### Step 2: Create Submission PR

1. Fork the main A2A Protocol repository
2. Create a feature branch: `git checkout -b projects/my-project`
3. Add your project to the `reference/examples/` directory
4. Update `PROJECTS.md` with your project details

```markdown
## My A2A Project

**Repository:** https://github.com/yourname/my-a2a-project  
**Type:** Agent Service / Agent Client / Extension  
**Status:** Production Ready  
**Maintainer:** Your Name (@yourname)

### Description
Brief description of what your project does.

### Quick Start
```bash
git clone https://github.com/yourname/my-a2a-project
cd my-a2a-project
pip install -r requirements.txt
python -m src.my_project.agent_server
```

### Supported Intents
- `echo` — Echo a message
- `process_data` — Process numeric data

### Testing
```bash
pytest tests/ -v --cov=src
```
```

5. Submit PR with title: `Projects: Add my-a2a-project`

### Step 3: Review Process

Reviews check for:
- ✅ Code quality and style
- ✅ Test coverage (>= 80%)
- ✅ Documentation completeness
- ✅ A2A Protocol compliance
- ✅ Security best practices
- ✅ No conflicts with existing projects

### Step 4: Merge and Announcement

Once approved:
- PR is merged into main repository
- Project listed on main website
- Announcement made to community
- Your project becomes discoverable by other agents

---

## Complete Examples

### Example 1: Simple Echo Agent

**File:** `examples/simple_echo_agent.py`

```python
"""
Minimal A2A Echo Agent
"""
import asyncio
from a2a.core.identity import create_did
from a2a.transport.http import HTTPTransport

async def main():
    # Step 1: Create identity
    agent = create_did(name="EchoAgent")
    print(f"DID: {agent.did}")
    
    # Step 2: Handle intents
    async def handle_intent(intent):
        if intent['goal'] == 'echo':
            return {'result': intent['params'].get('message')}
        return {'error': 'Unknown goal'}
    
    # Step 3: Start server
    transport = HTTPTransport()
    # ... Start HTTP server listening for requests ...

asyncio.run(main())
```

### Example 2: Multi-Agent Orchestrator

**File:** `examples/multi_agent_orchestrator.py`

```python
"""
Orchestrates calls to multiple agents
"""
import asyncio
from a2a.core.identity import create_did
from a2a.transport.http import HTTPTransport
from a2a.protocol.handshake import ClientHandshakeFSM

async def orchestrate():
    client = create_did(name="Orchestrator")
    transport = HTTPTransport()
    
    # Call multiple agents concurrently
    agents = [
        ("agent-1-did", "http://agent1:8000"),
        ("agent-2-did", "http://agent2:8000"),
        ("agent-3-did", "http://agent3:8000"),
    ]
    
    tasks = []
    for agent_did, endpoint in agents:
        fsm = ClientHandshakeFSM(client, agent_did)
        session_id, _ = await fsm.handshake(transport, endpoint)
        # Send intent...
        tasks.append(send_intent(session_id, endpoint, goal))
    
    results = await asyncio.gather(*tasks)
    return results

asyncio.run(orchestrate())
```

### Example 3: Data Processing Agent

**File:** `examples/data_processor_agent.py`

```python
"""
Agent that processes CSV data and returns statistics
"""
import csv
from typing import Dict, Any

async def handle_intent(intent: Dict[str, Any]):
    goal = intent.get('goal')
    
    if goal == 'analyze_csv':
        csv_data = intent['params'].get('data')
        result = {
            'row_count': len(csv_data),
            'columns': list(csv_data[0].keys()) if csv_data else [],
            'status': 'ok'
        }
        return result
    
    elif goal == 'compute_statistics':
        numbers = intent['params'].get('numbers', [])
        result = {
            'sum': sum(numbers),
            'mean': sum(numbers) / len(numbers) if numbers else 0,
            'count': len(numbers),
            'status': 'ok'
        }
        return result
    
    return {'error': f'Unknown goal: {goal}', 'status': 'error'}
```

---

## Troubleshooting

### Problem: "ImportError: No module named 'a2a'"

**Solution:**
```bash
pip install a2a-protocol>=1.0.0
# OR
pip install -e /path/to/a2a-protocol/reference
```

### Problem: "DID format invalid"

**Solution:**
DIDs must start with `did:`. Ensure you're using `create_did()` from `a2a.core.identity`.

```python
from a2a.core.identity import create_did
agent = create_did(name="MyAgent")
print(agent.did)  # Output: did:key:z6MkhaXgBZDvotzL8V6N1LXm1SmjYfHGdYnAYkBRCxq9WyKp
```

### Problem: "Test coverage below 80%"

**Solution:**
```bash
# Generate coverage report
pytest tests/ --cov=src --cov-report=html

# Open htmlcov/index.html to identify uncovered lines
# Add tests for those lines
# Re-run until coverage >= 80%
```

### Problem: "Handshake fails with 'signature mismatch'"

**Solution:**
Ensure:
1. Manifests are properly signed with private keys
2. Public keys match between agents
3. Nonces are fresh (not replayed)
4. Clocks are synchronized

### Problem: "Agent won't start on port 8000"

**Solution:**
```bash
# Check if port is already in use
lsof -i :8000

# Kill existing process
kill -9 <PID>

# Or use different port
python -m src.my_project.agent_server --port 8001
```

### Problem: "TLS certificate error in production"

**Solution:**
1. Generate proper TLS certificate:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
   ```

2. Configure HTTPTransport:
   ```python
   transport = HTTPTransport(
       verify_tls=True,
       cert_file="cert.pem",
       key_file="key.pem"
   )
   ```

---

## Summary

To add your project to the A2A ecosystem:

1. **Prepare** (30 min): Set up Git, virtualenv, install A2A
2. **Implement** (2-4 hrs): Create agent server and/or client
3. **Test** (1-2 hrs): Write tests, achieve 80%+ coverage
4. **Document** (1 hr): Write README, CONTRIBUTING, API docs
5. **Submit** (15 min): Create PR with project details
6. **Review** (1-3 days): Community review and feedback
7. **Merge** (5 min): PR approved and merged

**Total time:** 6-12 hours for complete integration

**Questions?** Open an issue or contact maintainers.

---

**Version:** 1.0.0  
**Last Updated:** February 2026  
**Status:** Complete and Ready for Contributions
