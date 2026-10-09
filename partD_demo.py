
from crypto_lab.pqc import (
    SCHEMES,
    transaction_size,
    size_multiplier,
    throughput_tps,
)

print("PART D - POST-QUANTUM SIGNATURE COMPARISON")
print("=" * 82)

print(
    f"{'Scheme':<24} {'Quantum safe':<14} "
    f"{'TX bytes':>10} {'Multiplier':>12} {'TPS':>10}"
)

print("-" * 82)

for name, scheme in SCHEMES.items():
    size = transaction_size(name)
    multiplier = size_multiplier(name)
    tps = throughput_tps(name)

    print(
        f"{scheme.name:<24} "
        f"{str(scheme.quantum_safe):<14} "
        f"{size:>10} "
        f"{multiplier:>11.2f}x "
        f"{tps:>10.2f}"
    )

print()
print("QUANTUM EXPOSURE ANALYSIS")
print("-" * 82)

exposure = {
    "Unspent P2PKH": "Public key is hidden until spending",
    "P2PK": "Public key is already exposed",
    "Reused address": "Public key may already be exposed",
    "Mempool transaction": "Public key exposed before confirmation",
    "Active Ethereum account": "Public key recoverable from a signature",
}

for output_type, explanation in exposure.items():
    print(f"{output_type}: {explanation}")
