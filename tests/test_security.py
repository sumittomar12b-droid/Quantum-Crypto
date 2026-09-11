"""
Unit and Integration Tests for Classical Security Controls (Layer 4).
"""

import pytest

from security.ml_kem_interface import MLKEMEngine, PQCAlgorithm
from security.symmetric_crypto import SymmetricCryptoEngine, ClassicalPayload
from security.session_nonce_manager import SessionNonceManager, SessionState
from security.identity_policy import IdentityPolicyEngine, UserRole
from security.audit_log import AuditLogger, AuditEventType


def test_ml_kem_encapsulation_decapsulation():
    """Tests ML-KEM-768 keypair generation, encapsulation, and shared secret recovery."""
    bob_keypair = MLKEMEngine.generate_keypair(PQCAlgorithm.ML_KEM_768)
    assert len(bob_keypair.public_key) == MLKEMEngine.PUBLIC_KEY_SIZE

    ciphertext, shared_secret_alice = MLKEMEngine.encapsulate(bob_keypair.public_key)
    shared_secret_bob = MLKEMEngine.decapsulate(bob_keypair.secret_key, ciphertext)

    assert shared_secret_alice == shared_secret_bob
    assert len(shared_secret_alice) == 32

    # Verify session key derivation
    session_key_alice = MLKEMEngine.derive_session_key(shared_secret_alice, "session-123")
    session_key_bob = MLKEMEngine.derive_session_key(shared_secret_bob, "session-123")
    assert session_key_alice == session_key_bob


def test_symmetric_payload_encryption():
    """Tests AES-256-GCM encryption of classical syndrome bits and metadata."""
    key = b"12345678901234567890123456789012"
    payload = ClassicalPayload(
        session_id="test-session-uuid",
        nonce="test-nonce-hex",
        timestamp="2026-09-11T18:00:00Z",
        corrections=[(0, 0), (1, 0), (0, 1), (1, 1)],
        metadata={"sender": "ALICE", "protocol": "QDS-v1.0"}
    )

    encrypted_blob = SymmetricCryptoEngine.encrypt_payload(key, payload)
    decrypted_payload = SymmetricCryptoEngine.decrypt_payload(key, encrypted_blob)

    assert decrypted_payload.session_id == payload.session_id
    assert decrypted_payload.nonce == payload.nonce
    assert decrypted_payload.corrections == payload.corrections


def test_session_replay_prevention():
    """Tests that replayed nonces and consumed resources are blocked."""
    manager = SessionNonceManager(default_ttl_seconds=300)
    session = manager.create_session("ALICE", "BOB", "msg_digest_abc")

    # Initial valid consumption
    consumed = manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
    assert consumed is True

    # Immediate replay attempt
    replayed = manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
    assert replayed is False


def test_identity_role_policy():
    """Tests RBAC access control rules."""
    engine = IdentityPolicyEngine()
    assert engine.can_sign("ALICE") is True
    assert engine.can_verify("ALICE") is False

    assert engine.can_sign("BOB") is False
    assert engine.can_verify("BOB") is True

    assert engine.can_arbitrate("CHARLIE") is True
    assert engine.can_sign("MALLORY") is False
    assert engine.can_verify("EVE") is False


def test_tamper_evident_audit_log_hash_chain():
    """Tests append-only cryptographic hash chaining and tamper detection."""
    logger = AuditLogger()

    logger.log_event(AuditEventType.SESSION_CREATED, "s-1", "ALICE", {"info": "init"})
    logger.log_event(AuditEventType.SIGNATURE_GENERATED, "s-1", "ALICE", {"L": 200})
    logger.log_event(AuditEventType.VERIFICATION_ACCEPTED, "s-1", "BOB", {"mismatches": 2})

    assert logger.verify_chain_integrity() is True
    assert len(logger.events) == 3

    # Tamper with an event in the chain
    logger.events[1].details["L"] = 9999
    assert logger.verify_chain_integrity() is False
