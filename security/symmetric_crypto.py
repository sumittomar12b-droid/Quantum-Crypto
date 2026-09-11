"""
Symmetric Authenticated Encryption (AES-256-GCM) for Classical Syndrome and Metadata.
Protects teleportation correction bits (m1, m2) and verification responses.
"""

from __future__ import annotations
from dataclasses import dataclass
import json
import os
from typing import Any, Dict, List, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


@dataclass
class ClassicalPayload:
    session_id: str
    nonce: str
    timestamp: str
    corrections: List[Tuple[int, int]]  # List of (m1, m2) pairs for each signature qubit
    metadata: Dict[str, Any]


class SymmetricCryptoEngine:
    """AES-256-GCM authenticated encryption for classical control plane."""

    @classmethod
    def encrypt_payload(
        cls,
        key: bytes,
        payload: ClassicalPayload,
        associated_data: bytes = b""
    ) -> bytes:
        """
        Serializes and encrypts ClassicalPayload into ciphertext || tag.
        """
        payload_json = json.dumps({
            "session_id": payload.session_id,
            "nonce": payload.nonce,
            "timestamp": payload.timestamp,
            "corrections": payload.corrections,
            "metadata": payload.metadata
        }).encode("utf-8")

        iv = os.urandom(12)  # 96-bit standard GCM IV

        if AESGCM is not None:
            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(iv, payload_json, associated_data)
            return iv + encrypted_data
        else:
            # Fallback XOR + HMAC if cryptography is not available
            import hmac
            import hashlib
            keystream = hashlib.sha3_256(key + iv).digest()
            expanded_keystream = (keystream * (len(payload_json) // len(keystream) + 1))[:len(payload_json)]
            ciphertext = bytes(a ^ b for a, b in zip(payload_json, expanded_keystream))
            tag = hmac.new(key, iv + associated_data + ciphertext, hashlib.sha3_256).digest()
            return iv + tag + ciphertext

    @classmethod
    def decrypt_payload(
        cls,
        key: bytes,
        ciphertext_blob: bytes,
        associated_data: bytes = b""
    ) -> ClassicalPayload:
        """
        Decrypts and deserializes ciphertext_blob back into ClassicalPayload.
        """
        iv = ciphertext_blob[:12]

        if AESGCM is not None:
            encrypted_data = ciphertext_blob[12:]
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(iv, encrypted_data, associated_data)
        else:
            import hmac
            import hashlib
            tag = ciphertext_blob[12:44]
            ciphertext = ciphertext_blob[44:]
            expected_tag = hmac.new(key, iv + associated_data + ciphertext, hashlib.sha3_256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Authentication tag mismatch! Data corrupted or tampered.")
            keystream = hashlib.sha3_256(key + iv).digest()
            expanded_keystream = (keystream * (len(ciphertext) // len(keystream) + 1))[:len(ciphertext)]
            decrypted_bytes = bytes(a ^ b for a, b in zip(ciphertext, expanded_keystream))

        data = json.loads(decrypted_bytes.decode("utf-8"))
        corrections = [tuple(c) for c in data["corrections"]]

        return ClassicalPayload(
            session_id=data["session_id"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            corrections=corrections,
            metadata=data["metadata"]
        )
