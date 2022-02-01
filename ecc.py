"""
Library containing helper classes for elliptic curve cryptography (ECC)
"""

class FieldElement:
    """An element belonging to the finite set"""
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
        num = pow(self.num, exponent, self.prime)
        return self.__class__(num, self.prime)
