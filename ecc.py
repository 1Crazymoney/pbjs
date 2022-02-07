"""
Library containing helper classes for elliptic curve cryptography (ECC)
"""

import hashlib
import hmac
from typing import Optional
from random import randint

A = 0
B = 7


class FieldElement:
    """An element belonging to a finite set"""
    def __init__(self, num: int, prime: int) -> "FieldElement":
        """
        Initializes a FiniteElement
        
        Args: 
            num (int): a number of integer type, e.g. 5
            prime (int): a prime number e.g 7

        Returns:
            FieldElement_7(5)
        """
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime - 1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        """String representation of a FieldElement"""
        return f'FieldElement_{self.prime}({self.num})'

    def __eq__(self, other: "FieldElement") -> bool:
        """
        Equality operator for objects of type FieldElement.
        Checks if the passed in element is equal to the instantiated element

        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            bool: True if equal, False otherwise
        """
        if other is None:
            return False

        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other: "FieldElement") -> bool:
        """
        Not equality operator for objects of type FieldElement.
        Checks if the passed in element is not equal to the instantiated element

        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            bool: True if not equal, False otherwise
        """
        return not (self == other)

    def __add__(self, other: "FieldElement") -> "FieldElement":
        """
        Adds a given field element to another

        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            FieldElement
        """

        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different fields')

        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        """
        Subtract a given field element from another

        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            FieldElement
        """
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different fields')

        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        """
        Multiply a given field element with another
        
        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            FieldElement
        """
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different fields')
        
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent: int) -> "FieldElement":
        """
        Raises the power of the field element to the given exponent

        Args:
            exponent (int): an integer

        Returns:
            FieldElement
        """
        n = exponent % (self.prime - 1)
        num = pow(self.num, exponent, self.prime)
        return self.__class__(num, self.prime)


    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        """
        Divides a field element with another
        
        Args:
            other (FieldElement): e.g. FieldElement_13(7)

        Returns:
            FieldElement
        """

        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different fields')

        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return self.__class__(num, self.prime)


class Point:
    """
    A point on an elliptic curve
    """
    def __init__(self, x: int, y: int, a: int, b: int) -> "Point":
        """
        Instantiates a point

        Args:
            x (int): x-coordinate value
            y (int): y-coordinate value
            a (int): constant coefficient of x
            b (int): constant

        """
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        # Point at Infinity
        if self.x is None and self.y is None:
            return

        if (self.y ** 2) != (self.x ** 3) + (a * x) + b:
            raise ValueError(f'({x}, {y}) is not on the curve')

    def __eq__(self, other: "Point") -> bool:
        """
        Overrides the equality operator '==' to check if two points are equal

        Args:
            other (Point): e.g. Point(-1, -1, 5, 7) 

        Returns:
            boolean: True if equal, false otherwise
        """
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b


    def __ne__(self, other: "Point") -> bool:
        """
        Checks if two points are not equal
        """
        return not (self == other)

    def __add__(self, other: "Point") -> "Point":
        """
        Adds one point to another
        """
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')

        if self.x is None:
            return other

        if other.x is None:
            return self

        # Vertical line 
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        # P1(x,y) != P2(x,y)
        if self.x != other.x:
            slope = (other.y - self.y) / (other.x - self.x)
            x = pow(slope, 2) - self.x - other.x
            y = slope*(self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # Both points at the same spot
        if self == other:
            slope = (3 * pow(self.x, 2) + self.a) / (2 * self.y)
            x = pow(slope, 2) - (2 * self.x)
            y = slope*(self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # P1 == P2 and y coordinate is 0
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

    def __rmul__(self, coefficient: int):
        """
        Scalar multiplication of a point
        """
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        
        return result

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 2**256 - 2**32 - 977


class S256Field(FieldElement):
    """
    An element belonging to the finite set of field F_p where 
    p = 2^256 - 2^32 - 977
    """
    def __init__(self, num: int, prime: int = None) -> "FieldElement":
        super().__init__(num, prime=P)

    def __repr__(self) -> str:
        return '{:x}'.format(self.num).zfill(64)


class S256Point(Point):
    """
    A point on the secp256k1 elliptic curve that bitcoin uses
    """
    def __init__(
        self, 
        x: Optional(int, S256Field), 
        y: Optional(int, S256Field), 
        a: int = None, 
        b: int = None
    ) -> "S256Point":

        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x = S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x = x, y = y, a = a, b = b)

    def __rmul__(self, coefficient: int) -> "S256Point":
        """
        Scalar multiplication of bitcoin elliptic curve point
        """
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z: int, sig: "Signature") -> bool:
        """
        Verifies a signature

        Args: 
            z (int): Signature hash/digital footprint of data
            sig (Signature): Digital signature

        Returns:
            True (bool)
        """
        s_inv = pow(sig.s, N -2, N)
        u = (z * s_inv) % N
        v = (sig.r * s_inv) % N
        total = (u * G) + (v * self)
        return total.x.num == sig.r

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)


class Signature:
    """
    Possesses create signatures, as well as methods to sign and verify 
    data
    """
    def __init__(self, r: int, s: int) -> None:
        """
        Initializes a new signature
        """
        self.r = r
        self.s = s

    def __repr__(self) -> str:
        """
        String representation of Signature
        """
        return "Signature({:x}, {:x})".format(self.r, self.x)


class PrivateKey:
    """
    Class to house private key/secret
    """
    def __init__(self, secret) -> None:
        """
        Initialize private key
        """
        self.secret: int = secret
        self.point: int = secret * G  # P = eG

    def hex(self) -> int:
        """
        Returns a hexadecimal representation of private key
        """
        return "{:x}".format(self.secret).zfill(64)

    def sign(self, z: int) -> Signature: 
        """
        Signs transaction data

        Args:
            z (int): signature hash, digital fingerprint of data

        Returns: 
            Signature(r,s): Digital signature
        """
        k = self.deterministic_k(z)
        r = (k * G).x.num 
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N/2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z: int):
        """
        Generates a deterministic integer k
        """
        k = b'\x00' * 32
        v = b'\x01' * 32

        if z > N:
            z -= N

        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256

        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()

        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')

            if candidate >= 1 and candidate < N:
                return candidate

            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()