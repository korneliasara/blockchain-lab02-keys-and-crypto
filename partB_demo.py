
import hashlib

from crypto_lab.curve import private_to_public
from crypto_lab.ecdsa import (
    sign,
    verify,
    looks_like_nonce_reuse,
    recover_private_key_from_nonce_reuse,
)

# Example values for the lab only
private_key = 12345
reused_nonce = 67890

message1 = hashlib.sha256(b"Pay Alice").digest()
message2 = hashlib.sha256(b"Pay Bob").digest()

# Sign two different messages with the same nonce
sig1 = sign(
    private_key, message1,
    nonce=reused_nonce,
    enforce_low_s=False
)

sig2 = sign(
    private_key, message2,
    nonce=reused_nonce,
    enforce_low_s=False
)

public_key = private_to_public(private_key)

print("PART B - ECDSA Nonce Reuse Demonstration")
print("---------------------------------------")

print("Signature 1 r:", hex(sig1.r))
print("Signature 2 r:", hex(sig2.r))

print("Signature 1 valid:",
      verify(public_key, message1, sig1))
print("Signature 2 valid:",
      verify(public_key, message2, sig2))

print("Same r value:",
      looks_like_nonce_reuse(sig1, sig2))

recovered_key = recover_private_key_from_nonce_reuse(
    sig1.r, sig1.s, message1, sig2.s, message2
)

print("Original private key:", private_key)
print("Recovered private key:", recovered_key)
print("Attack successful:", recovered_key == private_key)
