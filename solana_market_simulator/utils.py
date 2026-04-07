"""
Utility helpers shared across the simulator.

These are intentionally kept independent of the higher-level blockchain engine so they can be
imported from any module without creating architectural cycles.
"""

import hashlib
import json
import time
from typing import Any
from uuid import uuid4

from .constants import HASH_BYTES, SIGNATURE_BYTES


def now_ms() -> int:
    return int(time.time() * 1000)


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def placeholder_digest_hex(payload: bytes, digest_size_bytes: int) -> str:
    """
    Return a hex-encoded placeholder digest of a specific byte width.

    The digest width is expressed in bytes because Solana protocol sizes are byte-based.
    The returned string is hex text for readability, so its Python string length is twice
    the underlying byte length. Code that estimates protocol size must therefore use the
    byte-width constants above, not `len()` of the returned hex string.
    """
    return hashlib.blake2b(payload, digest_size=digest_size_bytes).hexdigest()


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return placeholder_digest_hex(encoded, HASH_BYTES)


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def make_address(name: str) -> str:
    # In Solana, an address is a public key that identifies an account or program.
    return f"addr_{name}"


def shortvec_length(value: int) -> int:
    """
    Return how many bytes Solana's shortvec variable-length integer encoding would use.

    Solana uses shortvec to encode lengths such as:
    - number of signatures
    - number of account keys
    - number of instructions
    - number of bytes in instruction data

    This helper does not serialize the value itself; it only tells us how many bytes the
    encoded length prefix would occupy so we can estimate transaction size.

    7 bits of the value are encoded per byte, and the high bit is a continuation flag.
    The helper keeps shifting by 7 bits until the remaining value is zero, counting how many
    bytes that takes.
    """
    if value < 0:
        raise ValueError("shortvec values must be non-negative")

    length = 1
    remaining = value >> 7
    while remaining:
        length += 1
        remaining >>= 7
    return length


def message_hash(message: dict[str, Any]) -> str:
    return stable_hash(message)


def simulate_signature_for_signer(message: dict[str, Any], signer_pubkey: str) -> str:
    # The payload is the exact byte string we pretend the signer is authorizing:
    # the compiled message bytes plus the signer's public key as a stand-in for signer-specific input.
    payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload += signer_pubkey.encode("utf-8")
    # We use blake2b here as a fast deterministic placeholder for a real Ed25519 signature.
    # This is not how Solana actually signs transactions; it is only a simulator-friendly stand-in.
    return placeholder_digest_hex(payload, SIGNATURE_BYTES)


def transaction_hash(transaction: dict[str, Any]) -> str:
    return stable_hash(transaction)
