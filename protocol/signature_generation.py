"""
Quantum Digital Signature (QDS) State Generation and Encoding.
Generates multi-qubit Pauli eigenstate sequences bound to SHA3-256 message digests.
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
from typing import List, Optional
import numpy as np

from .state_preparation import PauliBasis, PauliEigenstate, StatePreparation


@dataclass
class QuantumSignature:
    signature_id: str
    message: str
    message_digest: str
    signature_length: int
    bases: List[PauliBasis]
    bit_values: List[int]
    states: List[PauliEigenstate]
    timestamp: str

    def get_basis_sequence_string(self) -> str:
        return "".join([b.value for b in self.bases])

    def get_state_sequence_string(self) -> str:
        return " ".join([s.value for s in self.states])


class QDSSignatureGenerator:
    """Generates quantum signature state sequences for Alice."""

    @staticmethod
    def compute_message_digest(message: str | bytes) -> str:
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hashlib.sha3_256(message).hexdigest()

    @classmethod
    def generate_signature(
        cls,
        message: str,
        secret_key: bytes,
        signature_length: int = 200,
        signature_id: Optional[str] = None
    ) -> QuantumSignature:
        """
        Derives deterministic Pauli eigenstate sequences for message using HMAC-SHA3-256.
        """
        import datetime
        import uuid

        if signature_id is None:
            signature_id = str(uuid.uuid4())

        msg_digest = cls.compute_message_digest(message)
        
        # Derive pseudo-random stream from HMAC(secret_key, msg_digest)
        h = hmac.new(secret_key, msg_digest.encode("utf-8"), hashlib.sha3_256)
        seed_bytes = h.digest()
        seed_int = int.from_bytes(seed_bytes[:8], byteorder="big")
        
        rng = np.random.default_rng(seed_int)

        bases: List[PauliBasis] = []
        bit_values: List[int] = []
        states: List[PauliEigenstate] = []

        basis_options = [PauliBasis.Z, PauliBasis.X, PauliBasis.Y]

        for _ in range(signature_length):
            basis = basis_options[rng.integers(0, 3)]
            bit = int(rng.integers(0, 2))
            state = StatePreparation.from_basis_and_bit(basis, bit)

            bases.append(basis)
            bit_values.append(bit)
            states.append(state)

        return QuantumSignature(
            signature_id=signature_id,
            message=message,
            message_digest=msg_digest,
            signature_length=signature_length,
            bases=bases,
            bit_values=bit_values,
            states=states,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
