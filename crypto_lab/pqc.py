
from dataclasses import dataclass


@dataclass(frozen=True)
class Scheme:
    name: str
    public_key_bytes: int
    signature_bytes: int
    quantum_safe: bool


SCHEMES = {
    "ecdsa": Scheme(
        "ECDSA (secp256k1)", 33, 72, False
    ),
    "schnorr": Scheme(
        "Schnorr (BIP-340)", 32, 64, False
    ),
    "ml-dsa-44": Scheme(
        "ML-DSA-44", 1312, 2420, True
    ),
    "ml-dsa-65": Scheme(
        "ML-DSA-65", 1952, 3309, True
    ),
    "slh-dsa-128s": Scheme(
        "SLH-DSA-128s", 32, 7856, True
    ),
    "fn-dsa-512": Scheme(
        "FN-DSA-512", 897, 666, True
    ),
}


TX_OVERHEAD_BYTES = 110
BLOCK_CAPACITY_VBYTES = 1_000_000
BLOCK_INTERVAL_SECONDS = 600


def transaction_size(scheme_key: str, inputs: int = 1) -> int:
    """Estimate the size of a transaction."""
    if inputs < 1:
        raise ValueError("inputs must be positive")

    scheme = SCHEMES[scheme_key]

    return (
        TX_OVERHEAD_BYTES
        + inputs * (
            scheme.public_key_bytes
            + scheme.signature_bytes
        )
    )


def size_multiplier(scheme_key: str, inputs: int = 1) -> float:
    """Compare size against an ECDSA transaction."""
    return (
        transaction_size(scheme_key, inputs)
        / transaction_size("ecdsa", inputs)
    )


def throughput_tps(scheme_key: str, inputs: int = 1) -> float:
    """Estimate transactions per second."""
    return (
        BLOCK_CAPACITY_VBYTES
        / transaction_size(scheme_key, inputs)
        / BLOCK_INTERVAL_SECONDS
    )




def comparison_table() -> str:
    """Create a readable table comparing signature schemes."""
    lines = [
        "| Scheme | Quantum safe | Public key (B) | Signature (B) | TX size (B) |",
        "|---|---|---:|---:|---:|",
    ]

    for key, scheme in SCHEMES.items():
        size = transaction_size(key)

        lines.append(
            f"| {scheme.name} "
            f"| {'Yes' if scheme.quantum_safe else 'No'} "
            f"| {scheme.public_key_bytes} "
            f"| {scheme.signature_bytes} "
            f"| {size} |"
        )

    return "\n".join(lines)




def exposure_report() -> str:
    """Explain quantum exposure of Bitcoin and Ethereum keys."""
    return """
QUANTUM EXPOSURE REPORT

Harvest Now, Decrypt Later:
An attacker can collect public keys and signed transactions
today and save them for analysis with future quantum computers.
For blockchains, the main risk is recovering private keys from
exposed elliptic-curve public keys, rather than decrypting data.

Bitcoin P2PK:
The public key is directly visible in the output script.
These outputs are exposed to a future sufficiently powerful
quantum computer.

Bitcoin P2PKH:
The public key is initially hidden behind a hash.
When the coins are spent, the public key is revealed.
Reusing an address can leave remaining funds exposed.

Bitcoin mempool:
A spending transaction reveals the public key before
confirmation, creating a possible attack window.

Ethereum:
A public key can be recovered from a signed transaction.
Accounts that have sent transactions may therefore have
publicly recoverable keys.

Protection:
Quantum-resistant signature schemes could replace vulnerable
elliptic-curve signatures, but they often require larger
public keys and signatures.
"""
