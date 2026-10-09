
from crypto_lab.hdwallet import (
    mnemonic_to_seed,
    master_key_from_seed,
    derive_child,
    recover_parent_private_key,
    HARDENED_OFFSET,
)

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

root = master_key_from_seed(mnemonic_to_seed(TEST_MNEMONIC))

# Demonstrate the problem with a non-hardened child.
child = derive_child(root, 7)
public_parent = root.neuter()

recovered = recover_parent_private_key(
    public_parent,
    child.key,
    7,
)

print("PART C - BIP-32 Parent Key Recovery")
print("-----------------------------------")
print("Child index:", 7)
print("Parent extended public key available: True")
print("Child private key available: True")
print("Original parent key:", hex(root.key))
print("Recovered parent key:", hex(recovered))
print("Attack successful:", recovered == root.key)

# Show that hardened derivation cannot be performed
# from the parent's extended public key.
try:
    derive_child(public_parent, HARDENED_OFFSET)
except ValueError:
    print("Hardened derivation from public key: Rejected")
