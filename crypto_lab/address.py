
from Crypto.Hash import keccak

from crypto_lab.curve import Point, private_to_public


def keccak256(data: bytes) -> bytes:
    """Calculate the Keccak-256 hash used by Ethereum."""
    return keccak.new(digest_bits=256, data=data).digest()


def public_key_to_address(point: Point) -> bytes:
    """Convert a public key into a 20-byte Ethereum address."""
    if point.is_infinity:
        raise ValueError("invalid public key")

    x_bytes = point.x.to_bytes(32, "big")
    y_bytes = point.y.to_bytes(32, "big")

    # Ethereum hashes x + y, without the 0x04 prefix.
    public_key_bytes = x_bytes + y_bytes

    return keccak256(public_key_bytes)[-20:]


def to_checksum_address(address: bytes | str) -> str:
    """Apply the EIP-55 checksum using letter capitalization."""
    if isinstance(address, bytes):
        if len(address) != 20:
            raise ValueError("address must be 20 bytes")
        address_hex = address.hex()
    else:
        address_hex = address.lower().removeprefix("0x")
        if len(address_hex) != 40:
            raise ValueError("address must contain 40 hex characters")
        try:
            bytes.fromhex(address_hex)
        except ValueError:
            raise ValueError("invalid hexadecimal address")

    hashed = keccak256(address_hex.encode("ascii")).hex()

    checksummed = ""

    for i, character in enumerate(address_hex):
        if character in "abcdef" and int(hashed[i], 16) >= 8:
            checksummed += character.upper()
        else:
            checksummed += character

    return "0x" + checksummed


def address_from_private_key(private_key: int) -> str:
    """Derive a checksummed Ethereum address from a private key."""
    public_key = private_to_public(private_key)
    raw_address = public_key_to_address(public_key)
    return to_checksum_address(raw_address)


def is_valid_checksum_address(address: str) -> bool:
    """Check whether an Ethereum address has a valid EIP-55 checksum."""

    if not isinstance(address, str):
        return False

    body = address.removeprefix("0x")

    if len(body) != 40:
        return False

    try:
        bytes.fromhex(body)
    except ValueError:
        return False

    # All-lowercase and all-uppercase forms are accepted,
    # but do not provide checksum protection.
    if body == body.lower() or body == body.upper():
        return True

    # Mixed-case addresses must have the correct EIP-55 checksum.
    return to_checksum_address(body) == "0x" + body
