
from dataclasses import dataclass

# Parameters of Bitcoin's secp256k1 curve
P = 2**256 - 2**32 - 977
A = 0
B = 7

# Order of the generator point
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Generator point coordinates
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


# Special point acting as the identity element
INFINITY = Point(None, None)

# Standard generator point
G = Point(GX, GY)


def inverse_mod(value: int, modulus: int = P) -> int:
    """Find the modular multiplicative inverse."""
    if value % modulus == 0:
        raise ZeroDivisionError("inverse does not exist")

    return pow(value, modulus - 2, modulus)


def is_on_curve(point: Point) -> bool:
    """Check whether a point belongs to secp256k1."""
    if point.is_infinity:
        return True

    if point.x is None or point.y is None:
        return False

    return (point.y**2 - point.x**3 - 7) % P == 0




def negate(point: Point) -> Point:
    """Return the opposite of a curve point."""
    if point.is_infinity:
        return INFINITY

    return Point(point.x, (-point.y) % P)


def double(point: Point) -> Point:
    """Calculate point + point."""
    if point.is_infinity:
        return INFINITY

    if point.y == 0:
        return INFINITY

    slope = (
        (3 * point.x**2 + A)
        * inverse_mod(2 * point.y)
    ) % P

    x3 = (slope**2 - 2 * point.x) % P
    y3 = (slope * (point.x - x3) - point.y) % P

    return Point(x3, y3)


def add(p1: Point, p2: Point) -> Point:
    """Add two points on the curve."""
    if p1.is_infinity:
        return p2

    if p2.is_infinity:
        return p1

    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:
            return INFINITY

        return double(p1)

    slope = (
        (p2.y - p1.y)
        * inverse_mod(p2.x - p1.x)
    ) % P

    x3 = (slope**2 - p1.x - p2.x) % P
    y3 = (slope * (p1.x - x3) - p1.y) % P

    return Point(x3, y3)


def scalar_mul(k: int, point: Point = G) -> Point:
    """Multiply a curve point using Double-and-Add."""
    if k < 0:
        return scalar_mul(-k, negate(point))

    if k == 0 or point.is_infinity:
        return INFINITY

    result = INFINITY
    current = point

    while k > 0:
        if k & 1:
            result = add(result, current)

        current = double(current)
        k >>= 1

    return result


def private_to_public(private_key: int) -> Point:
    """Derive a public key from a private key."""
    if not 1 <= private_key < N:
        raise ValueError("private key out of range")

    return scalar_mul(private_key, G)



def scalar_mul_ladder(k: int, point: Point = G) -> Point:
    """Multiply a point using the Montgomery ladder."""

    if k < 0:
        return scalar_mul_ladder(-k, negate(point))

    if k == 0 or point.is_infinity:
        return INFINITY

    r0 = INFINITY
    r1 = point

    for bit in bin(k)[2:]:
        if bit == "0":
            r1 = add(r0, r1)
            r0 = double(r0)
        else:
            r0 = add(r0, r1)
            r1 = double(r1)

    return r0




def serialize_public_key(
    point: Point, compressed: bool = True
) -> bytes:
    """Convert a public key point into bytes."""
    if point.is_infinity or not is_on_curve(point):
        raise ValueError("invalid public key point")

    x_bytes = point.x.to_bytes(32, "big")

    if compressed:
        prefix = b"\x03" if point.y % 2 else b"\x02"
        return prefix + x_bytes

    y_bytes = point.y.to_bytes(32, "big")
    return b"\x04" + x_bytes + y_bytes


def deserialize_public_key(data: bytes) -> Point:
    """Convert public key bytes back into a curve point."""

    if len(data) == 65 and data[0] == 0x04:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")

    elif len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")

        if x >= P:
            raise ValueError("invalid x-coordinate")

        y_squared = (x**3 + 7) % P
        y = pow(y_squared, (P + 1) // 4, P)

        if y * y % P != y_squared:
            raise ValueError("x does not correspond to a curve point")

        if y % 2 != data[0] % 2:
            y = P - y

    else:
        raise ValueError("invalid public key encoding")

    if not (0 <= x < P and 0 <= y < P):
        raise ValueError("public key coordinates out of range")

    point = Point(x, y)

    if not is_on_curve(point):
        raise ValueError("public key is not on the curve")

    return point
