from helper import (
    encode_varint, 
    int_to_little_endian, 
    murmur3,
    bit_field_to_bytes
)
from network import GenericMessage

BIP37_CONSTANT = 0xfba4c795


class BloomFilter:
    """
    Attributes and methods for bloom filters
    """
    def __init__(self, size: int, function_count: int, tweak: int) -> None:
        """
        Instantiates a new bloom filter
        """
        self.size = size
        self.bit_field = [0] * (size * 8)
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item):
        for i in range(self.function_count):
            seed = i * BIP37_CONSTANT + self.tweak
            h = murmur3(item, seed=seed)
            bit = h % (self.size * 8)
            self.bit_field[bit] = 1

    def filterload(self, flag=1):
        payload = encode_varint(self.size)
        payload += self.filter_bytes()
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        payload += int_to_little_endian(flag, 1)

        return GenericMessage(b'filterload', payload)

    def filter_bytes(self):
        return bit_field_to_bytes(self.bit_field)