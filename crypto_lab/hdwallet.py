
import hashlib
import unicodedata


def mnemonic_to_seed(
    mnemonic: str,
    passphrase: str = ""
) -> bytes:
    """Convert a BIP-39 mnemonic into a 64-byte seed."""

    # Normalize the mnemonic and passphrase.
    normalized_mnemonic = unicodedata.normalize(
        "NFKD", " ".join(mnemonic.split())
    )

    normalized_salt = unicodedata.normalize(
        "NFKD", "mnemonic" + passphrase
    )

    # Use PBKDF2-HMAC-SHA512 with 2048 iterations.
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        normalized_mnemonic.encode("utf-8"),
        normalized_salt.encode("utf-8"),
        2048,
        dklen=64,
    )

    return seed



import hmac
from dataclasses import dataclass

from crypto_lab.curve import N, Point, private_to_public

from crypto_lab.curve import (
    G, N, add, scalar_mul, serialize_public_key
)

@dataclass(frozen=True)
class ExtendedKey:
    key: int | None
    public_point: Point
    chain_code: bytes
    depth: int = 0
    child_number: int = 0

    @property
    def is_private(self) -> bool:
        return self.key is not None

    def neuter(self):
        """Return a public-only version of this key."""
        return ExtendedKey(
            key=None,
            public_point=self.public_point,
            chain_code=self.chain_code,
            depth=self.depth,
            child_number=self.child_number,
        )


def master_key_from_seed(seed: bytes) -> ExtendedKey:
    """Create a BIP-32 master extended private key."""
    if not 16 <= len(seed) <= 64:
        raise ValueError("seed must be 16 to 64 bytes")

    digest = hmac.new(
        b"Bitcoin seed",
        seed,
        hashlib.sha512,
    ).digest()

    private_key = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]

    if not 1 <= private_key < N:
        raise ValueError("invalid master private key")

    return ExtendedKey(
        key=private_key,
        public_point=private_to_public(private_key),
        chain_code=chain_code,
    )



HARDENED_OFFSET = 2**31


def derive_child(parent: ExtendedKey, index: int) -> ExtendedKey:
    """Derive a BIP-32 child key."""

    if not 0 <= index < 2**32:
        raise ValueError("invalid child index")

    hardened = index >= HARDENED_OFFSET

    if hardened:
        if parent.key is None:
            raise ValueError("hardened derivation requires a private key")

        data = (
            b"\x00"
            + parent.key.to_bytes(32, "big")
            + index.to_bytes(4, "big")
        )
    else:
        data = (
            serialize_public_key(parent.public_point, compressed=True)
            + index.to_bytes(4, "big")
        )

    digest = hmac.new(
        parent.chain_code,
        data,
        hashlib.sha512
    ).digest()

    tweak = int.from_bytes(digest[:32], "big")
    child_chain_code = digest[32:]

    if tweak >= N:
        raise ValueError("invalid child derivation")

    if parent.key is not None:
        child_private_key = (parent.key + tweak) % N

        if child_private_key == 0:
            raise ValueError("invalid child private key")

        child_public_key = private_to_public(child_private_key)

    else:
        child_private_key = None
        child_public_key = add(
            parent.public_point,
            scalar_mul(tweak, G)
        )

        if child_public_key.is_infinity:
            raise ValueError("invalid child public key")

    return ExtendedKey(
        key=child_private_key,
        public_point=child_public_key,
        chain_code=child_chain_code,
        depth=parent.depth + 1,
        child_number=index,
    )




def derive_path(root: ExtendedKey, path: str) -> ExtendedKey:
    """Derive a key using a BIP-32 path such as m/44'/60'/0'/0/0."""
    parts = path.split("/")

    if not parts or parts[0] != "m":
        raise ValueError("path must start with m")

    current = root

    for part in parts[1:]:
        if not part:
            raise ValueError("empty path component")

        hardened = part.endswith(("'", "h", "H"))
        number_text = part[:-1] if hardened else part

        if not number_text.isdecimal():
            raise ValueError("invalid path component")

        number = int(number_text)

        if number >= HARDENED_OFFSET:
            raise ValueError("path index out of range")

        index = number + HARDENED_OFFSET if hardened else number
        current = derive_child(current, index)

    return current


def ethereum_account(
    mnemonic: str,
    index: int = 0,
    passphrase: str = "",
) -> ExtendedKey:
    """Derive an Ethereum key using the standard BIP-44 path."""
    if not 0 <= index < HARDENED_OFFSET:
        raise ValueError("invalid account address index")

    seed = mnemonic_to_seed(mnemonic, passphrase)
    master = master_key_from_seed(seed)

    path = f"m/44'/60'/0'/0/{index}"
    return derive_path(master, path)



def recover_parent_private_key(
    parent_public: ExtendedKey,
    child_private_key: int,
    index: int,
) -> int:
    """Recover a non-hardened parent private key.

    Educational demonstration only.
    """
    if parent_public.key is not None:
        raise ValueError("expected a public-only parent")

    
    if not 0 <= index < HARDENED_OFFSET:
        raise ValueError(
            "hardened children are immune to this parent-key recovery attack"
        )


    if not 1 <= child_private_key < N:
        raise ValueError("invalid child private key")

    data = (
        serialize_public_key(
            parent_public.public_point,
            compressed=True,
        )
        + index.to_bytes(4, "big")
    )

    digest = hmac.new(
        parent_public.chain_code,
        data,
        hashlib.sha512,
    ).digest()

    tweak = int.from_bytes(digest[:32], "big")

    if tweak >= N:
        raise ValueError("invalid derivation tweak")

    recovered_key = (child_private_key - tweak) % N

    if not 1 <= recovered_key < N:
        raise ValueError("invalid recovered private key")

    if private_to_public(recovered_key) != parent_public.public_point:
        raise ValueError("recovered key does not match parent")

    return recovered_key




def entropy_to_mnemonic(
    entropy: bytes,
    wordlist: list[str],
) -> list[str]:
    """Convert BIP-39 entropy into a mnemonic phrase."""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("invalid entropy length")

    if len(wordlist) != 2048 or len(set(wordlist)) != 2048:
        raise ValueError("wordlist must contain 2048 unique words")

    entropy_bits = "".join(
        f"{byte:08b}" for byte in entropy
    )

    checksum_length = len(entropy) * 8 // 32
    checksum = hashlib.sha256(entropy).digest()

    checksum_bits = "".join(
        f"{byte:08b}" for byte in checksum
    )[:checksum_length]

    combined = entropy_bits + checksum_bits

    indices = [
        int(combined[i:i + 11], 2)
        for i in range(0, len(combined), 11)
    ]

    return [wordlist[i] for i in indices]




def mnemonic_to_entropy(
    words: list[str] | str,
    wordlist: list[str],
) -> bytes:
    """Recover BIP-39 entropy and verify its checksum."""

    if isinstance(words, str):
        words = words.split()

    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("invalid mnemonic word count")

    if len(wordlist) != 2048 or len(set(wordlist)) != 2048:
        raise ValueError("wordlist must contain 2048 unique words")

    # Find the 11-bit index of each word.
    lookup = {word: i for i, word in enumerate(wordlist)}

    try:
        indices = [lookup[word] for word in words]
    except KeyError:
        raise ValueError("unknown mnemonic word") from None

    bits = "".join(f"{index:011b}" for index in indices)

    entropy_length = len(bits) * 32 // 33
    checksum_length = len(bits) - entropy_length

    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[entropy_length:]

    entropy = int(entropy_bits, 2).to_bytes(
        entropy_length // 8, "big"
    )

    expected_checksum = "".join(
        f"{byte:08b}" for byte in hashlib.sha256(entropy).digest()
    )[:checksum_length]

    if checksum_bits != expected_checksum:
        raise ValueError("invalid mnemonic checksum")

    return entropy




def parse_path(path: str) -> list[int]:
    """Convert a BIP-32 derivation path into child indices."""
    if not isinstance(path, str):
        raise ValueError("path must be a string")

    parts = path.split("/")

    if not parts or parts[0] != "m":
        raise ValueError("path must start with m")

    indices = []

    for part in parts[1:]:
        if not part:
            raise ValueError("empty path component")

        hardened = part.endswith(("'", "h", "H"))
        number_text = part[:-1] if hardened else part

        if not number_text.isdecimal():
            raise ValueError("invalid path component")

        number = int(number_text)

        if number >= HARDENED_OFFSET:
            raise ValueError("path index out of range")

        if hardened:
            number += HARDENED_OFFSET

        indices.append(number)

    return indices




def format_path(indices: list[int]) -> str:
    """Convert BIP-32 child indices into a derivation path."""
    parts = ["m"]

    for index in indices:
        if not 0 <= index < 2**32:
            raise ValueError("invalid child index")

        if index >= HARDENED_OFFSET:
            number = index - HARDENED_OFFSET
            parts.append(f"{number}'")
        else:
            parts.append(str(index))

    return "/".join(parts)
