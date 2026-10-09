# Blockchain Lab 02 — Keys and Cryptography

This repository contains my Python implementation of Blockchain Lab 02.

## Features

- Elliptic-curve arithmetic using secp256k1
- Double-and-Add and Montgomery ladder
- ECDSA signing, verification, and public-key recovery
- RFC 6979 deterministic signatures
- ECDSA nonce-reuse attack demonstration
- BIP-39 mnemonic and seed generation
- BIP-32 hierarchical deterministic wallets
- BIP-44 Ethereum derivation paths
- Ethereum addresses and EIP-55 checksums
- Post-quantum signature size comparisons

## Requirements

- Python 3.12
- pytest
- pycryptodome

## Running the tests

Install the dependencies:

`pip install pytest pycryptodome`

Run my own tests:

`python -m pytest test_crypto.py -q`

## Test results

- My own tests: **81 passed**
- Professor's reference tests: **64 passed**
- Total: **145 passing test cases**

## Notes

This project is for educational purposes only. The cryptographic implementation should not be used to manage real cryptocurrency funds.