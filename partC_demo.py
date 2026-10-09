
from crypto_lab.hdwallet import (
    mnemonic_to_seed,
    master_key_from_seed,
    ethereum_account,
)
from crypto_lab.address import (
    public_key_to_address,
    to_checksum_address,
)

# Public test mnemonic from the BIP-39 specification.
# Never use this phrase for real cryptocurrency.
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

print("PART C - Hierarchical Deterministic Wallets")
print("-------------------------------------------")

seed = mnemonic_to_seed(TEST_MNEMONIC)
master = master_key_from_seed(seed)

print("BIP-39 seed:", seed.hex())
print("Master private key:", hex(master.key))
print("Master chain code:", master.chain_code.hex())

print("\nFirst three Ethereum addresses:")

for index in range(3):
    node = ethereum_account(TEST_MNEMONIC, index)
    address = to_checksum_address(
        public_key_to_address(node.public_point)
    )

    print(f"m/44'/60'/0'/0/{index}: {address}")

print("\nPassphrase comparison:")

for passphrase in ["", "correct horse", "correct horse "]:
    node = ethereum_account(
        TEST_MNEMONIC,
        index=0,
        passphrase=passphrase,
    )

    address = to_checksum_address(
        public_key_to_address(node.public_point)
    )

    print(f"Passphrase {passphrase!r}: {address}")
