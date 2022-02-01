"""
Library containing helper classes for elliptic curve cryptography (ECC)
"""

class FieldElement:
    """An element belonging to the finite set"""
    def __init__(self, num: int, prime: int) -> None:
        """initialize a FiniteElement"""
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime - 1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        """String representation of a FieldElement"""
        return f'FieldElement_{self.prime}({self.num})'

    def __eq__(self, other: "FieldElement") -> bool:
        """Equality operator for objects of type FieldElement"""
        if other is None:
            return False

        return self.num == other.num and self.prime == other.prime