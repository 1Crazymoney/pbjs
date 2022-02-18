"""
Block implementation
"""
from io import BytesIO
from typing_extensions import Self
from helper import hash256, int_to_little_endian, little_endian_to_int

class Block:
    """
    Attributes and methods that pertain to a bitcoin block of transactions
    """
    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce) -> None:
        """
        Instantiates a new block
        """
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    @classmethod
    def parse(cls, s: BytesIO) -> Self:
        """
        Parses a 80-byte encoding of a block into a Block object
        """
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)

        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self) -> bytes:
        """
        Serializes a Block object into a bytes
        """
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce

        return result

    def hash(self):
        """
        Hash256 a Block object. Returns the LE SHA value
        """
        s = self.serialize()
        sha = hash256(s)

        return sha[::-1]