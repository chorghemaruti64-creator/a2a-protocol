"""
Agent Manifest validation and signature verification.

Implements:
- Manifest schema validation (Pydantic)
- Manifest signature verification
- Version compatibility
- DID resolution
"""

import json
import time
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field, validator

from a2a.security.crypto import JWS, sha256, CryptoError, KeyPair
from a2a.core.errors import InvalidManifestError


class PublicKeyModel(BaseModel):
    """JWK-format public key."""
    kid: str
    kty: str = "EC"
    alg: str = "EdDSA"
    use: str = "sig"
    key: str

    class Config:
        frozen = True


class EndpointModel(BaseModel):
    """Agent endpoint."""
    type: str
    url: str
    transport: str = "http"
    auth_required: bool = False

    @validator("type")
    def valid_type(cls, v):
        if v not in ("handshake", "request", "stream", "custom"):
            raise ValueError(f"Invalid endpoint type: {v}")
        return v

    @validator("url")
    def valid_url(cls, v):
        if not v.startswith("https://"):
            raise ValueError("Endpoint URL must use HTTPS")
        return v

    class Config:
        frozen = True


class CapabilityModel(BaseModel):
    """Agent capability."""
    id: str
    version: Optional[str] = None
    description: Optional[str] = None
    requires_capabilities: list = Field(default_factory=list)

    class Config:
        frozen = True


class PolicyModel(BaseModel):
    """Agent policy constraints."""
    rate_limit: Optional[int] = None
    rate_period: Optional[int] = None
    session_timeout: int = 3600
    max_payload_size: int = 10485760
    data_retention: str = "session"
    require_encryption: bool = False
    max_concurrent_sessions: int = 100
    allowed_intents: list = Field(default_factory=list)
    blocked_intents: list = Field(default_factory=list)

    class Config:
        frozen = True


class TrustChainEntry(BaseModel):
    """Trust chain endorsement."""
    issuer: str
    issued_at: int
    expires_at: Optional[int] = None
    trust_level: str
    signature: str

    @validator("trust_level")
    def valid_trust_level(cls, v):
        if v not in ("self", "verified", "delegated"):
            raise ValueError(f"Invalid trust level: {v}")
        return v

    class Config:
        frozen = True


class AgentManifestModel(BaseModel):
    """Agent Manifest (Agent Card) per A2A Spec v1.0."""
    manifest_version: str
    agent_did: str
    agent_id: str
    public_keys: list[PublicKeyModel]
    endpoints: list[EndpointModel]
    capabilities: list[CapabilityModel] = Field(default_factory=list)
    policy: Optional[PolicyModel] = None
    trust_chain: list[TrustChainEntry] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    published_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    manifest_hash: Optional[str] = None
    manifest_signature: Optional[str] = None

    @validator("manifest_version")
    def valid_version(cls, v):
        if v != "1.0":
            raise ValueError(f"Unsupported manifest version: {v}")
        return v

    @validator("agent_did")
    def valid_did(cls, v):
        if not v.startswith("did:"):
            raise ValueError(f"Invalid DID format: {v}")
        return v

    @validator("public_keys")
    def min_keys(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one public key required")
        if len(v) > 10:
            raise ValueError("Maximum 10 public keys allowed")
        return v

    @validator("endpoints")
    def min_endpoints(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one endpoint required")
        return v

    class Config:
        frozen = False  # Allow mutation during creation


class ManifestValidator:
    """Validate and verify Agent Manifests."""

    @staticmethod
    def validate_schema(manifest_dict: Dict[str, Any]) -> AgentManifestModel:
        """
        Validate manifest against JSON schema.

        Args:
            manifest_dict: Manifest as dict

        Returns:
            Validated AgentManifestModel

        Raises:
            InvalidManifestError: If schema validation fails
        """
        try:
            # Convert nested dicts to Pydantic models
            return AgentManifestModel(**manifest_dict)
        except Exception as e:
            raise InvalidManifestError(f"Manifest schema validation failed: {e}")

    @staticmethod
    def verify_signature(manifest_dict: Dict[str, Any], public_key_bytes: bytes) -> bool:
        """
        Verify manifest signature.

        Manifest signature is a JWS over the manifest (excluding signature fields).

        Args:
            manifest_dict: Manifest as dict (with manifest_signature)
            public_key_bytes: Ed25519 public key (32 bytes)

        Returns:
            True if signature is valid

        Raises:
            InvalidManifestError: If signature verification fails
        """
        try:
            jws = manifest_dict.get("manifest_signature")
            if not jws:
                raise InvalidManifestError("Manifest signature missing")

            # Decode payload from JWS (without verification yet)
            payload = JWS.decode_payload(jws)
            if not payload:
                raise InvalidManifestError("Invalid JWS format")

            # Verify JWS signature
            valid, decoded_payload = JWS.verify(jws, public_key_bytes)
            if not valid:
                raise InvalidManifestError("Manifest signature verification failed")

            # Verify manifest hash matches
            if "manifest_hash" not in decoded_payload:
                raise InvalidManifestError("Manifest hash missing from JWS payload")

            expected_hash = decoded_payload["manifest_hash"]
            manifest_copy = manifest_dict.copy()
            # Remove both signature fields before hashing
            manifest_copy.pop("manifest_signature", None)
            manifest_copy.pop("manifest_hash", None)

            computed_hash = f"sha256:{sha256(json.dumps(manifest_copy, sort_keys=True, separators=(',', ':')).encode())}"

            if computed_hash != expected_hash:
                raise InvalidManifestError(f"Manifest hash mismatch: {computed_hash} != {expected_hash}")

            return True

        except InvalidManifestError:
            raise
        except Exception as e:
            raise InvalidManifestError(f"Signature verification error: {e}")

    @staticmethod
    def verify_expiry(manifest_dict: Dict[str, Any]) -> bool:
        """
        Verify manifest is not expired.

        Args:
            manifest_dict: Manifest as dict

        Returns:
            True if manifest is valid

        Raises:
            InvalidManifestError: If manifest is expired
        """
        expires_at = manifest_dict.get("expires_at")
        if expires_at and expires_at < int(time.time()):
            raise InvalidManifestError("Manifest is expired")
        return True

    @staticmethod
    def load_and_verify(manifest_dict: Dict[str, Any], public_key_bytes: bytes) -> AgentManifestModel:
        """
        Load, validate, and verify a manifest.

        Args:
            manifest_dict: Manifest as dict
            public_key_bytes: Ed25519 public key (32 bytes)

        Returns:
            Validated and verified manifest

        Raises:
            InvalidManifestError: If any validation or verification fails
        """
        # 1. Check expiry first (before signature verification, as signature covers manifest content)
        ManifestValidator.verify_expiry(manifest_dict)

        # 2. Verify signature
        ManifestValidator.verify_signature(manifest_dict, public_key_bytes)

        # 3. Validate schema
        manifest = ManifestValidator.validate_schema(manifest_dict)

        return manifest


class DIDResolver:
    """Resolve DIDs to public keys."""

    @staticmethod
    def resolve_did_key(did: str) -> bytes:
        """
        Resolve did:key to public key.

        Format: did:key:z<base58(multicodec_bytes)>
        where multicodec_bytes = [0x12, 0x20] + public_key (32 bytes)

        Args:
            did: DID string (did:key:z...)

        Returns:
            Ed25519 public key (32 bytes)

        Raises:
            InvalidManifestError: If DID is invalid
        """
        try:
            if not did.startswith("did:key:z"):
                raise ValueError("Invalid did:key format")

            from a2a.security.crypto import base58_decode

            # Extract base58 portion
            b58_part = did[9:]  # Skip "did:key:z"
            multicodec_bytes = base58_decode(b58_part)

            # Check multicodec prefix (0x1220 = Ed25519 public key)
            if len(multicodec_bytes) < 34 or multicodec_bytes[0] != 0x12 or multicodec_bytes[1] != 0x20:
                raise ValueError("Invalid multicodec prefix")

            return multicodec_bytes[2:]  # Skip 2-byte prefix, return 32-byte public key
        except Exception as e:
            raise InvalidManifestError(f"DID resolution failed: {e}")

    @staticmethod
    def resolve(did: str) -> bytes:
        """
        Resolve DID to public key.

        Currently supports: did:key

        Args:
            did: DID string

        Returns:
            Ed25519 public key (32 bytes)

        Raises:
            InvalidManifestError: If DID resolution fails
        """
        if did.startswith("did:key:"):
            return DIDResolver.resolve_did_key(did)
        else:
            raise InvalidManifestError(f"Unsupported DID method: {did}")
