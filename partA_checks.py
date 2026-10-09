from crypto_lab.curve import (
    G, N, INFINITY, add, double, negate,
    scalar_mul, scalar_mul_ladder, is_on_curve
)

checks = {
    "G on curve": is_on_curve(G),
    "n*G is the identity": scalar_mul(N, G) == INFINITY,
    "(n-1)*G + G is the identity": (
        add(scalar_mul(N - 1, G), G) == INFINITY
    ),
    "G + G == 2*G": add(G, G) == double(G),
    "Double-and-Add == Montgomery ladder": (
        scalar_mul(12345, G) == scalar_mul_ladder(12345, G)
    ),
}

for name, result in checks.items():
    print(f"{name}: {result}")

two_g = double(G)
print(f"2G x-coordinate: 0x{two_g.x:064x}")
