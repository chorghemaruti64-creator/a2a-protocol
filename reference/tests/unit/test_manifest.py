"""
Unit tests for Agent Manifest validation and verification.

Tests:
- Schema validation
- Signature verification
- DID resolution
- Expiry checks
- Error handling
"""

import pytest
import json
import time
from a2a.core.manifest import (
    ManifestValidator,
    DIDResolver,
    AgentManifestModel,
    PublicKeyModel,
    EndpointModel,
    PolicyModel,
)
from a2a.core.errors import InvalidManifestError
from a2a.security.crypto import KeyPair, JWS, sha256


@pytest.fixture
def keypair():
    """Generate test keypair."""
    return KeyPair.generate()


@pytest.fixture
def valid_manifest_dict(keypair):
    """Create a valid manifest dict."""
    public_key_b64 = keypair.public_key_base64()
    
    return {
        "manifest_version": "1.0",
        "agent_did": keypair.get_did_key(),
        "agent_id": "test-agent-v1",
        "public_keys": [
            {
                "kid": "sig-2024-01",
                "kty": "EC",
                "alg": "EdDSA",
                "use": "sig",
                "key": public_key_b64,
            }
        ],
        "endpoints": [
            {
                "type": "handshake",
                "url": "https://test.example.com/a2a/handshake",
                "transport": "http",
                "auth_required": True,
            }
        ],
        "capabilities": [
            {
                "id": "nlp.translate",
                "version": "1.0.0",
                "description": "Translate text",
            }
        ],
        "policy": {
            "rate_limit": 1000,
            "rate_period": 3600,
            "session_timeout": 3600,
            "max_payload_size": 10485760,
            "data_retention": "24h",
        },
        "published_at": int(time.time()),
    }


@pytest.fixture
def signed_manifest(valid_manifest_dict, keypair):
    """Create a signed manifest."""
    # Compute manifest hash
    manifest_copy = valid_manifest_dict.copy()
    canonical_json = json.dumps(manifest_copy, sort_keys=True, separators=(',', ':'))
    manifest_hash = f"sha256:{sha256(canonical_json.encode())}"
    
    # Create payload for JWS
    payload = {
        "manifest": manifest_copy,
        "manifest_hash": manifest_hash,
        "timestamp": int(time.time()),
        "issuer": valid_manifest_dict["agent_did"],
    }
    
    # Sign
    jws = JWS.create(payload, keypair, kid="sig-2024-01")
    
    # Add signature to manifest
    valid_manifest_dict["manifest_hash"] = manifest_hash
    valid_manifest_dict["manifest_signature"] = jws
    
    return valid_manifest_dict


class TestManifestValidation:
    """Test manifest schema validation."""
    
    def test_valid_manifest(self, valid_manifest_dict):
        """Valid manifest passes schema validation."""
        manifest = ManifestValidator.validate_schema(valid_manifest_dict)
        assert manifest.manifest_version == "1.0"
        assert manifest.agent_id == "test-agent-v1"
    
    def test_missing_manifest_version(self, valid_manifest_dict):
        """Missing manifest_version fails validation."""
        del valid_manifest_dict["manifest_version"]
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_invalid_manifest_version(self, valid_manifest_dict):
        """Invalid manifest version fails."""
        valid_manifest_dict["manifest_version"] = "2.0"
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_missing_agent_did(self, valid_manifest_dict):
        """Missing agent_did fails."""
        del valid_manifest_dict["agent_did"]
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_invalid_did_format(self, valid_manifest_dict):
        """Invalid DID format fails."""
        valid_manifest_dict["agent_did"] = "not-a-did"
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_missing_public_keys(self, valid_manifest_dict):
        """Missing public_keys fails."""
        del valid_manifest_dict["public_keys"]
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_empty_public_keys(self, valid_manifest_dict):
        """Empty public_keys fails."""
        valid_manifest_dict["public_keys"] = []
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_missing_endpoints(self, valid_manifest_dict):
        """Missing endpoints fails."""
        del valid_manifest_dict["endpoints"]
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_endpoint_http_not_https(self, valid_manifest_dict):
        """HTTP endpoint fails (HTTPS required)."""
        valid_manifest_dict["endpoints"][0]["url"] = "http://test.example.com/a2a/handshake"
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)
    
    def test_invalid_endpoint_type(self, valid_manifest_dict):
        """Invalid endpoint type fails."""
        valid_manifest_dict["endpoints"][0]["type"] = "invalid"
        with pytest.raises(InvalidManifestError):
            ManifestValidator.validate_schema(valid_manifest_dict)


class TestSignatureVerification:
    """Test manifest signature verification."""
    
    def test_valid_signature(self, signed_manifest, keypair):
        """Valid signature verifies."""
        assert ManifestValidator.verify_signature(signed_manifest, keypair.public_key_bytes())
    
    def test_missing_signature(self, valid_manifest_dict, keypair):
        """Missing signature fails."""
        with pytest.raises(InvalidManifestError, match="signature missing"):
            ManifestValidator.verify_signature(valid_manifest_dict, keypair.public_key_bytes())
    
    def test_invalid_jws_format(self, signed_manifest, keypair):
        """Invalid JWS format fails."""
        signed_manifest["manifest_signature"] = "not.a.valid.jws"
        with pytest.raises(InvalidManifestError):
            ManifestValidator.verify_signature(signed_manifest, keypair.public_key_bytes())
    
    def test_wrong_public_key(self, signed_manifest):
        """Verification fails with wrong public key."""
        wrong_keypair = KeyPair.generate()
        with pytest.raises(InvalidManifestError, match="verification failed"):
            ManifestValidator.verify_signature(signed_manifest, wrong_keypair.public_key_bytes())
    
    def test_tampered_manifest_hash(self, signed_manifest, keypair):
        """Tampered manifest fails verification."""
        # Modify manifest after signing
        signed_manifest["agent_id"] = "different-id"
        with pytest.raises(InvalidManifestError, match="hash mismatch"):
            ManifestValidator.verify_signature(signed_manifest, keypair.public_key_bytes())


class TestExpiryCheck:
    """Test manifest expiry validation."""
    
    def test_not_expired(self, valid_manifest_dict):
        """Not-expired manifest passes."""
        valid_manifest_dict["expires_at"] = int(time.time()) + 3600  # 1 hour from now
        assert ManifestValidator.verify_expiry(valid_manifest_dict)
    
    def test_expired(self, valid_manifest_dict):
        """Expired manifest fails."""
        valid_manifest_dict["expires_at"] = int(time.time()) - 1  # Already expired
        with pytest.raises(InvalidManifestError, match="expired"):
            ManifestValidator.verify_expiry(valid_manifest_dict)
    
    def test_no_expiry(self, valid_manifest_dict):
        """No expiry check passes."""
        assert ManifestValidator.verify_expiry(valid_manifest_dict)


class TestDIDResolution:
    """Test DID resolution."""
    
    def test_resolve_did_key(self, keypair):
        """Resolve did:key to public key."""
        did = keypair.get_did_key()
        resolved_key = DIDResolver.resolve_did_key(did)
        assert resolved_key == keypair.public_key_bytes()
    
    def test_invalid_did_key_format(self):
        """Invalid did:key format fails."""
        with pytest.raises(InvalidManifestError):
            DIDResolver.resolve_did_key("did:key:invalid")
    
    def test_resolve_unsupported_did_method(self):
        """Unsupported DID method fails."""
        with pytest.raises(InvalidManifestError, match="Unsupported"):
            DIDResolver.resolve("did:web:example.com")


class TestFullManifestFlow:
    """Test complete manifest load and verify flow."""
    
    def test_load_and_verify_valid(self, signed_manifest, keypair):
        """Load and verify valid manifest."""
        manifest = ManifestValidator.load_and_verify(
            signed_manifest,
            keypair.public_key_bytes()
        )
        assert manifest.agent_id == "test-agent-v1"
        assert manifest.manifest_version == "1.0"
    
    def test_load_and_verify_invalid_schema(self, valid_manifest_dict, keypair):
        """Load and verify fails on invalid schema."""
        del valid_manifest_dict["agent_id"]
        with pytest.raises(InvalidManifestError):
            ManifestValidator.load_and_verify(valid_manifest_dict, keypair.public_key_bytes())
    
    def test_load_and_verify_invalid_signature(self, signed_manifest):
        """Load and verify fails on invalid signature."""
        wrong_keypair = KeyPair.generate()
        with pytest.raises(InvalidManifestError):
            ManifestValidator.load_and_verify(
                signed_manifest,
                wrong_keypair.public_key_bytes()
            )
    
    def test_load_and_verify_expired(self, signed_manifest, keypair):
        """Load and verify fails on expired manifest."""
        signed_manifest["expires_at"] = int(time.time()) - 1
        with pytest.raises(InvalidManifestError, match="expired"):
            ManifestValidator.load_and_verify(signed_manifest, keypair.public_key_bytes())


class TestManifestCreation:
    """Test creating valid manifests."""
    
    def test_create_manifest_from_dict(self, valid_manifest_dict):
        """Create manifest from valid dict."""
        manifest = AgentManifestModel(**valid_manifest_dict)
        assert manifest.manifest_version == "1.0"
        assert len(manifest.public_keys) == 1
        assert len(manifest.endpoints) == 1
    
    def test_create_with_policy(self, valid_manifest_dict):
        """Create manifest with policy."""
        policy_dict = {
            "rate_limit": 500,
            "rate_period": 1800,
            "session_timeout": 7200,
        }
        valid_manifest_dict["policy"] = policy_dict
        manifest = AgentManifestModel(**valid_manifest_dict)
        assert manifest.policy.rate_limit == 500
    
    def test_create_with_capabilities(self, valid_manifest_dict):
        """Create manifest with capabilities."""
        assert len(valid_manifest_dict["capabilities"]) == 1
        manifest = AgentManifestModel(**valid_manifest_dict)
        assert len(manifest.capabilities) == 1
        assert manifest.capabilities[0].id == "nlp.translate"
