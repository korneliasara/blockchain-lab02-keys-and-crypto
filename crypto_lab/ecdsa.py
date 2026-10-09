import hashlib
import hmac


from dataclasses import dataclass
from crypto_lab.curve import (
    G, N, P, Point, add, negate, scalar_mul,
    inverse_mod, is_on_curve
)



@dataclass(frozen=True)
class Signature:
    r: int
    s: int
    recovery_id: int = 0

    def to_bytes(self) -> bytes:
        """Encode r and s as a 64-byte compact signature."""
        return (
            self.r.to_bytes(32, "big")
            + self.s.to_bytes(32, "big")
        )

    def to_der(self) -> bytes:
        """Encode an ECDSA signature in DER format."""

        def encode_integer(value: int) -> bytes:
            if not 0 <= value < N:
                raise ValueError("invalid signature integer")

            encoded = value.to_bytes(
                max(1, (value.bit_length() + 7) // 8),
                "big",
            )

            # DER INTEGER values are signed.
            # Add 00 when the highest bit is set.
            if encoded[0] & 0x80:
                encoded = b"\x00" + encoded

            return b"\x02" + bytes([len(encoded)]) + encoded

        r_encoded = encode_integer(self.r)
        s_encoded = encode_integer(self.s)

        content = r_encoded + s_encoded

        return b"\x30" + bytes([len(content)]) + content



def sign(
    private_key: int,
    message_hash: bytes,
    nonce: int | None = None,
    enforce_low_s: bool = True,
) -> Signature:
    """Sign a message using ECDSA."""
    if not 1 <= private_key < N:
        raise ValueError("invalid private key")

    if len(message_hash) != 32:
        raise ValueError("message hash must be 32 bytes")

    if nonce is None:
        nonce = rfc6979_nonce(private_key, message_hash)

    if not 1 <= nonce < N:
        raise ValueError("invalid nonce")

    z = int.from_bytes(message_hash, "big")
    point = scalar_mul(nonce, G)

    r = point.x % N
    if r == 0:
        raise ValueError("invalid r value")

    s = (inverse_mod(nonce, N) * (z + r * private_key)) % N
    if s == 0:
        raise ValueError("invalid s value")

    recovery_id = point.y % 2
    if point.x >= N:
        recovery_id |= 2

    # Choose the low-s form of the signature.
    if enforce_low_s and s > N // 2:
        s = N - s
        recovery_id ^= 1

    return Signature(r, s, recovery_id)



def verify(public_key, message_hash: bytes, signature: Signature) -> bool:
    """Verify an ECDSA signature using a public key."""
    if len(message_hash) != 32:
        return False

    r, s = signature.r, signature.s

    if not (1 <= r < N and 1 <= s < N):
        return False

    z = int.from_bytes(message_hash, "big")
    w = inverse_mod(s, N)

    u1 = (z * w) % N
    u2 = (r * w) % N

    point = add(
        scalar_mul(u1, G),
        scalar_mul(u2, public_key)
    )

    if point.is_infinity:
        return False

    return point.x % N == r




def rfc6979_nonce(private_key: int, message_hash: bytes) -> int:
    """Generate a deterministic ECDSA nonce using RFC 6979."""
    if not 1 <= private_key < N:
        raise ValueError("invalid private key")

    if len(message_hash) != 32:
        raise ValueError("message hash must be 32 bytes")

    private_bytes = private_key.to_bytes(32, "big")
    hashed_number = int.from_bytes(message_hash, "big") % N
    hash_bytes = hashed_number.to_bytes(32, "big")

    v = b"\x01" * 32
    k = b"\x00" * 32

    k = hmac.new(
        k, v + b"\x00" + private_bytes + hash_bytes,
        hashlib.sha256
    ).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    k = hmac.new(
        k, v + b"\x01" + private_bytes + hash_bytes,
        hashlib.sha256
    ).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")

        if 1 <= candidate < N:
            return candidate

        k = hmac.new(
            k, v + b"\x00", hashlib.sha256
        ).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()




def recover_public_key(
    message_hash: bytes,
    signature: Signature,
) -> Point:
    """Recover the public key from an ECDSA signature."""
    if len(message_hash) != 32:
        raise ValueError("message hash must be 32 bytes")

    r, s = signature.r, signature.s
    recovery_id = signature.recovery_id

    if not (1 <= r < N and 1 <= s < N):
        raise ValueError("invalid signature")

    if not 0 <= recovery_id <= 3:
        raise ValueError("invalid recovery ID")

    x = r + (recovery_id // 2) * N

    if x >= P:
        raise ValueError("invalid recovery point")

    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)

    if y * y % P != y_squared:
        raise ValueError("point not on curve")

    if y % 2 != recovery_id % 2:
        y = P - y

    R = Point(x, y)

    if not is_on_curve(R):
        raise ValueError("invalid curve point")

    if not scalar_mul(N, R).is_infinity:
        raise ValueError("invalid point order")

    z = int.from_bytes(message_hash, "big")
    r_inv = inverse_mod(r, N)

    public_key = scalar_mul(
        r_inv,
        add(
            scalar_mul(s, R),
            negate(scalar_mul(z, G))
        )
    )

    if not verify(public_key, message_hash, signature):
        raise ValueError("recovered key does not verify")

    return public_key




def looks_like_nonce_reuse(sig1: Signature, sig2: Signature) -> bool:
    """Check whether two signatures have the same r value."""
    return sig1.r == sig2.r



def recover_private_key_from_nonce_reuse(
    r: int,
    s1: int,
    msg1: bytes,
    s2: int,
    msg2: bytes,
) -> int:
    """Recover a private key when an ECDSA nonce was reused.

    Handles both original and low-s normalized signatures.
    Educational demonstration only.
    """
    if len(msg1) != 32 or len(msg2) != 32:
        raise ValueError("message hashes must be 32 bytes")

    if not (1 <= r < N and 1 <= s1 < N and 1 <= s2 < N):
        raise ValueError("invalid signature values")

    z1 = int.from_bytes(msg1, "big")
    z2 = int.from_bytes(msg2, "big")

    # Low-s normalization may replace s with N-s.
    for original_s1 in (s1, N - s1):
        for original_s2 in (s2, N - s2):
            difference = (original_s1 - original_s2) % N

            if difference == 0:
                continue

            nonce = (
                (z1 - z2) * inverse_mod(difference, N)
            ) % N

            if nonce == 0:
                continue

            # Check whether this nonce produces the expected r.
            point = scalar_mul(nonce, G)

            if point.x % N != r:
                continue

            recovered_key = (
                (original_s1 * nonce - z1)
                * inverse_mod(r, N)
            ) % N

            if 1 <= recovered_key < N:
                return recovered_key

    raise ValueError("could not recover private key")

