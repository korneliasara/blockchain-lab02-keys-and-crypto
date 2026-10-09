
import pytest

from crypto_lab.curve import (
    P,
    G,
    INFINITY,
    Point,
    inverse_mod,
    is_on_curve,
)


def test_field_prime():
    assert P == 2**256 - 2**32 - 977


def test_generator_on_curve():
    assert is_on_curve(G)


def test_point_at_infinity():
    assert is_on_curve(INFINITY)
    assert INFINITY.is_infinity


def test_invalid_point():
    assert not is_on_curve(Point(1, 1))


def test_modular_inverse():
    for value in [1, 2, 3, 12345]:
        inverse = inverse_mod(value)
        assert (value * inverse) % P == 1


def test_inverse_zero():
    with pytest.raises(ZeroDivisionError):
        inverse_mod(0)




from crypto_lab.curve import add, double, negate


def test_add_identity():
    assert add(G, INFINITY) == G
    assert add(INFINITY, G) == G


def test_opposite_points():
    assert add(G, negate(G)) == INFINITY


def test_double_generator():
    expected = Point(
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )

    assert double(G) == expected


def test_double_equals_add():
    assert double(G) == add(G, G)


def test_result_on_curve():
    assert is_on_curve(double(G))
    assert is_on_curve(add(G, double(G)))




from crypto_lab.curve import (
    N,
    scalar_mul,
    private_to_public,
)


def test_scalar_multiplication_zero():
    assert scalar_mul(0, G) == INFINITY


def test_scalar_multiplication_one():
    assert scalar_mul(1, G) == G


def test_scalar_multiplication_two():
    assert scalar_mul(2, G) == double(G)


def test_generator_order():
    assert scalar_mul(N, G) == INFINITY


def test_scalar_multiplication_negative():
    assert scalar_mul(-1, G) == negate(G)


def test_private_to_public():
    assert private_to_public(1) == G
    assert private_to_public(2) == double(G)


def test_invalid_private_key():
    for value in (0, -1, N, N + 1):
        with pytest.raises(ValueError):
            private_to_public(value)




from crypto_lab.curve import scalar_mul_ladder


def test_ladder_matches_double_and_add():
    for k in [1, 2, 3, 7, 15, 100, 12345]:
        assert scalar_mul_ladder(k, G) == scalar_mul(k, G)


def test_ladder_generator_order():
    assert scalar_mul_ladder(N, G) == INFINITY


def test_ladder_negative_scalar():
    assert scalar_mul_ladder(-3, G) == scalar_mul(-3, G)


def test_ladder_zero():
    assert scalar_mul_ladder(0, G) == INFINITY




from crypto_lab.curve import (
    serialize_public_key,
    deserialize_public_key,
)


def test_compressed_public_key():
    encoded = serialize_public_key(G, compressed=True)

    assert len(encoded) == 33
    assert encoded[0] == 0x02
    assert deserialize_public_key(encoded) == G


def test_uncompressed_public_key():
    encoded = serialize_public_key(G, compressed=False)

    assert len(encoded) == 65
    assert encoded[0] == 0x04
    assert deserialize_public_key(encoded) == G


def test_public_key_roundtrip():
    for private_key in [1, 2, 7, 12345]:
        point = private_to_public(private_key)

        for compressed in (True, False):
            encoded = serialize_public_key(point, compressed)
            decoded = deserialize_public_key(encoded)

            assert decoded == point


def test_invalid_public_key_encoding():
    with pytest.raises(ValueError):
        deserialize_public_key(b"\x02" + b"\x01" * 10)


def test_invalid_uncompressed_point():
    invalid = (
        b"\x04"
        + (1).to_bytes(32, "big")
        + (1).to_bytes(32, "big")
    )

    with pytest.raises(ValueError):
        deserialize_public_key(invalid)



import hashlib
from crypto_lab.ecdsa import sign, verify


def test_ecdsa_sign_verify():
    private_key = 12345
    public_key = private_to_public(private_key)
    message = hashlib.sha256(b"Hello blockchain").digest()

    signature = sign(private_key, message, nonce=67890)

    assert verify(public_key, message, signature)


def test_ecdsa_wrong_message():
    private_key = 12345
    public_key = private_to_public(private_key)

    message1 = hashlib.sha256(b"Message A").digest()
    message2 = hashlib.sha256(b"Message B").digest()

    signature = sign(private_key, message1, nonce=67890)

    assert not verify(public_key, message2, signature)


def test_ecdsa_invalid_nonce():
    message = hashlib.sha256(b"Test").digest()

    with pytest.raises(ValueError):
        sign(12345, message, nonce=0)




from crypto_lab.ecdsa import rfc6979_nonce


def test_rfc6979_deterministic():
    message = hashlib.sha256(b"Blockchain Lab 02").digest()
    private_key = 12345

    nonce1 = rfc6979_nonce(private_key, message)
    nonce2 = rfc6979_nonce(private_key, message)

    assert nonce1 == nonce2
    assert 1 <= nonce1 < N


def test_rfc6979_different_messages():
    private_key = 12345

    message1 = hashlib.sha256(b"Message A").digest()
    message2 = hashlib.sha256(b"Message B").digest()

    nonce1 = rfc6979_nonce(private_key, message1)
    nonce2 = rfc6979_nonce(private_key, message2)

    assert nonce1 != nonce2



def test_deterministic_signing():
    message = hashlib.sha256(b"Deterministic ECDSA").digest()

    sig1 = sign(12345, message)
    sig2 = sign(12345, message)

    assert sig1 == sig2
    assert verify(private_to_public(12345), message, sig1)


def test_low_s_signature():
    for i in range(10):
        message = hashlib.sha256(f"message {i}".encode()).digest()
        signature = sign(12345, message)

        assert signature.s <= N // 2


def test_high_s_also_verifies():
    message = hashlib.sha256(b"Signature malleability").digest()
    public_key = private_to_public(12345)

    signature = sign(12345, message)

    high_s = type(signature)(
        signature.r,
        N - signature.s,
        signature.recovery_id ^ 1,
    )

    assert verify(public_key, message, high_s)


def test_different_messages_have_different_signatures():
    message1 = hashlib.sha256(b"First message").digest()
    message2 = hashlib.sha256(b"Second message").digest()

    assert sign(12345, message1) != sign(12345, message2)




from crypto_lab.ecdsa import recover_public_key, Signature


def test_public_key_recovery():
    private_key = 12345
    message = hashlib.sha256(b"Recover my key").digest()

    signature = sign(private_key, message)
    recovered = recover_public_key(message, signature)

    assert recovered == private_to_public(private_key)


def test_recovery_with_explicit_nonce():
    private_key = 12345
    message = hashlib.sha256(b"Another recovery").digest()

    signature = sign(private_key, message, nonce=67890)
    recovered = recover_public_key(message, signature)

    assert recovered == private_to_public(private_key)


def test_invalid_recovery_id():
    message = hashlib.sha256(b"Invalid recovery").digest()
    signature = Signature(1, 1, 5)

    with pytest.raises(ValueError):
        recover_public_key(message, signature)




from crypto_lab.ecdsa import (
    looks_like_nonce_reuse,
    recover_private_key_from_nonce_reuse,
)


def test_nonce_reuse_detection():
    key = 12345
    nonce = 67890

    msg1 = hashlib.sha256(b"Pay Alice").digest()
    msg2 = hashlib.sha256(b"Pay Bob").digest()

    sig1 = sign(key, msg1, nonce=nonce, enforce_low_s=False)
    sig2 = sign(key, msg2, nonce=nonce, enforce_low_s=False)

    assert looks_like_nonce_reuse(sig1, sig2)


def test_nonce_reuse_recovers_private_key():
    key = 12345
    nonce = 67890

    msg1 = hashlib.sha256(b"Pay Alice").digest()
    msg2 = hashlib.sha256(b"Pay Bob").digest()

    sig1 = sign(key, msg1, nonce=nonce, enforce_low_s=False)
    sig2 = sign(key, msg2, nonce=nonce, enforce_low_s=False)

    recovered = recover_private_key_from_nonce_reuse(
        sig1.r, sig1.s, msg1, sig2.s, msg2
    )

    assert recovered == key


def test_different_nonces_have_different_r():
    key = 12345
    msg1 = hashlib.sha256(b"Message 1").digest()
    msg2 = hashlib.sha256(b"Message 2").digest()

    sig1 = sign(key, msg1, nonce=11111)
    sig2 = sign(key, msg2, nonce=22222)

    assert not looks_like_nonce_reuse(sig1, sig2)




from crypto_lab.hdwallet import mnemonic_to_seed


TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_mnemonic_seed_length():
    seed = mnemonic_to_seed(TEST_MNEMONIC)
    assert len(seed) == 64


def test_mnemonic_deterministic():
    seed1 = mnemonic_to_seed(TEST_MNEMONIC)
    seed2 = mnemonic_to_seed(TEST_MNEMONIC)

    assert seed1 == seed2


def test_mnemonic_passphrase_changes_seed():
    seed1 = mnemonic_to_seed(TEST_MNEMONIC)
    seed2 = mnemonic_to_seed(
        TEST_MNEMONIC,
        passphrase="correct horse"
    )

    assert seed1 != seed2



from crypto_lab.hdwallet import master_key_from_seed


def test_master_key_generation():
    seed = mnemonic_to_seed(TEST_MNEMONIC)
    master = master_key_from_seed(seed)

    assert master.key is not None
    assert 1 <= master.key < N
    assert len(master.chain_code) == 32


def test_master_public_key():
    seed = mnemonic_to_seed(TEST_MNEMONIC)
    master = master_key_from_seed(seed)

    assert master.public_point == private_to_public(master.key)


def test_master_key_deterministic():
    seed = mnemonic_to_seed(TEST_MNEMONIC)

    master1 = master_key_from_seed(seed)
    master2 = master_key_from_seed(seed)

    assert master1 == master2


def test_neuter_removes_private_key():
    seed = mnemonic_to_seed(TEST_MNEMONIC)
    master = master_key_from_seed(seed)

    public_only = master.neuter()

    assert public_only.key is None
    assert not public_only.is_private
    assert public_only.public_point == master.public_point
    assert public_only.chain_code == master.chain_code




from crypto_lab.hdwallet import derive_child, HARDENED_OFFSET


def test_normal_child_derivation():
    master = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))
    child = derive_child(master, 0)

    assert child.key is not None
    assert child.depth == 1
    assert child.child_number == 0


def test_hardened_child_derivation():
    master = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))
    child = derive_child(master, HARDENED_OFFSET)

    assert child.key is not None
    assert child.depth == 1


def test_public_child_matches_private_child():
    master = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    private_child = derive_child(master, 7)
    public_child = derive_child(master.neuter(), 7)

    assert private_child.public_point == public_child.public_point
    assert private_child.chain_code == public_child.chain_code


def test_hardened_child_from_public_key_rejected():
    master = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    with pytest.raises(ValueError):
        derive_child(master.neuter(), HARDENED_OFFSET)


def test_different_child_indices():
    master = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    child0 = derive_child(master, 0)
    child1 = derive_child(master, 1)

    assert child0.public_point != child1.public_point




from crypto_lab.hdwallet import derive_path, ethereum_account


def test_derive_path_matches_manual_derivation():
    root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    manual = derive_child(root, HARDENED_OFFSET + 44)
    manual = derive_child(manual, HARDENED_OFFSET + 60)
    manual = derive_child(manual, HARDENED_OFFSET)
    manual = derive_child(manual, 0)
    manual = derive_child(manual, 0)

    assert derive_path(root, "m/44'/60'/0'/0/0") == manual


def test_ethereum_account_first_key():
    node = ethereum_account(TEST_MNEMONIC, index=0)

    assert node.key is not None
    assert node.depth == 5


def test_ethereum_accounts_are_different():
    account0 = ethereum_account(TEST_MNEMONIC, 0)
    account1 = ethereum_account(TEST_MNEMONIC, 1)

    assert account0.public_point != account1.public_point


def test_ethereum_passphrase_changes_key():
    normal = ethereum_account(TEST_MNEMONIC, 0)
    changed = ethereum_account(
        TEST_MNEMONIC, 0, passphrase="correct horse"
    )

    assert normal.public_point != changed.public_point


def test_invalid_derivation_path():
    root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    with pytest.raises(ValueError):
        derive_path(root, "44'/60'/0'/0/0")




from crypto_lab.address import (
    keccak256,
    public_key_to_address,
    to_checksum_address,
    address_from_private_key,
)


def test_keccak256_empty_string():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0"
        "e500b653ca82273b7bfad8045d85a470"
    )


def test_ethereum_address_length():
    public_key = private_to_public(1)
    address = public_key_to_address(public_key)

    assert len(address) == 20


def test_ethereum_known_private_key():
    # Published Ethereum address corresponding to key 1.
    assert address_from_private_key(1) == (
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    )


def test_eip55_known_vector():
    address = "52908400098527886e0f7030069857d2e4169ee7"

    assert to_checksum_address(address) == (
        "0x52908400098527886E0F7030069857D2E4169EE7"
    )




from crypto_lab.address import is_valid_checksum_address


def test_valid_eip55_address():
    address = "0x52908400098527886E0F7030069857D2E4169EE7"

    assert is_valid_checksum_address(address)


def test_invalid_eip55_checksum():
    valid = address_from_private_key(1)

    # Change the case of one letter to invalidate the checksum.
    chars = list(valid)
    for i in range(2, len(chars)):
        if chars[i].isalpha():
            chars[i] = chars[i].swapcase()
            break

    invalid = "".join(chars)

    assert not is_valid_checksum_address(invalid)


def test_lowercase_address_accepted():
    address = address_from_private_key(1).lower()

    assert is_valid_checksum_address(address)


def test_invalid_ethereum_address_length():
    assert not is_valid_checksum_address("0x1234")




from crypto_lab.hdwallet import recover_parent_private_key


def test_recover_parent_private_key():
    root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

    child = derive_child(root, 7)
    public_parent = root.neuter()

    recovered = recover_parent_private_key(
        public_parent, child.key, 7
    )

    assert recovered == root.key


def test_hardened_parent_recovery_rejected():
    root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))
    child = derive_child(root, HARDENED_OFFSET)

    with pytest.raises(ValueError):
        recover_parent_private_key(
            root.neuter(), child.key, HARDENED_OFFSET
        )


def test_wrong_child_index_rejected():
    root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))
    child = derive_child(root, 7)

    with pytest.raises(ValueError):
        recover_parent_private_key(
            root.neuter(), child.key, 8
        )



from crypto_lab.pqc import (
    SCHEMES,
    transaction_size,
    size_multiplier,
    throughput_tps,
)


def test_ecdsa_transaction_size():
    assert transaction_size("ecdsa") == 215


def test_ml_dsa_transaction_is_larger():
    assert transaction_size("ml-dsa-44") == 3842
    assert size_multiplier("ml-dsa-44") > 17


def test_post_quantum_throughput_lower():
    assert throughput_tps("ml-dsa-44") < throughput_tps("ecdsa")


def test_quantum_safe_classification():
    assert not SCHEMES["ecdsa"].quantum_safe
    assert not SCHEMES["schnorr"].quantum_safe
    assert SCHEMES["ml-dsa-44"].quantum_safe
    assert SCHEMES["slh-dsa-128s"].quantum_safe




from crypto_lab.hdwallet import entropy_to_mnemonic


def synthetic_wordlist():
    return [f"word{i:04d}" for i in range(2048)]


@pytest.mark.parametrize("byte_count,word_count", [
    (16, 12),
    (20, 15),
    (24, 18),
    (28, 21),
    (32, 24),
])
def test_entropy_to_mnemonic_length(byte_count, word_count):
    entropy = b"\x00" * byte_count
    words = entropy_to_mnemonic(
        entropy, synthetic_wordlist()
    )

    assert len(words) == word_count




from crypto_lab.hdwallet import mnemonic_to_entropy


def test_mnemonic_entropy_roundtrip():
    wordlist = synthetic_wordlist()
    entropy = bytes(range(16))

    words = entropy_to_mnemonic(entropy, wordlist)
    recovered = mnemonic_to_entropy(words, wordlist)

    assert recovered == entropy


def test_mnemonic_invalid_checksum():
    wordlist = synthetic_wordlist()
    entropy = bytes(range(16))

    words = entropy_to_mnemonic(entropy, wordlist)

    # Replace the last word with one having a
    # different checksum but the same entropy bits.
    last_index = wordlist.index(words[-1])
    words[-1] = wordlist[last_index ^ 1]

    with pytest.raises(ValueError, match="checksum"):
        mnemonic_to_entropy(words, wordlist)
