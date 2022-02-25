"""
Block implementation
"""
from io import BytesIO
from typing_extensions import Self
from helper import hash256, int_to_little_endian, little_endian_to_int, bits_to_target, merkle_root


class Block:
    """
    Attributes and methods that pertain to a bitcoin block of transactions
    """
    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None) -> Self:
        """
        Instantiates a new block
        """
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

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

    def validate_merkle_root(self):
        """
        Validate the merkle root
        """
        hashes = [h[::-1] for h in self.tx_hashes]
        root = merkle_root(hashes=hashes)
        return root[::-1] == self.merkle_root

    def bip9(self) -> bool:
        """
        BIP0009: 29 different features can be signalled with the version field
        at the same time
        """
        return self.version >> 29 == 0b001

    def bip91(self) -> bool:
        """
        Signals BIP0091:
        """
        return self.version >> 4 & 1 == 1

    def bip141(self):
        """
        Signals BIP0141:
        """
        return self.version >> 1 & 1 == 1

    def difficulty(self):
        """
        Returns the block difficulty based on bits
        """
        lowest = 0xffff * 256 ** (0x1d - 3)
        return lowest / self.target()

    def target(self):
        """
        Returns the proof-of-work target based on bits
        """
        return bits_to_target(self.bits)

    def pow(self) -> bool:
        """
        Checks the POW
        """
        sha = hash256(self.serialize())
        proof = little_endian_to_int(sha)
        return proof < self.target()