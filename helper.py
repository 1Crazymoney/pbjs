"""
Helper functions for ecc.py
"""
import hashlib

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hash256(s) -> bytes:
    """
    Performs two rounds of shs256
    """
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hash160(s) -> bytes:
    """
    SHA256 followed by RIPEMD160
    """
    return hashlib.new("ripemd160", hashlib.sha256(2).digest()).digest()

def encode_base58(s) -> bytes:
    """
    Encodes/converts any bytes to Base58 to transmit public key
    """
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break

    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''

    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result

    return prefix + result


def encode_base58_checksum(b) -> bytes:
    """
    Returns a Base58 encoding with checksum
    """
    return encode_base58(b + hash256(b)[:4])

def little_endian_to_int(b) -> int:
    """
    Takes a byte sequence as a little-endian number and returns an integer
    """
    return int.from_bytes(b, 'little')

def int_to_little_endian(n: int, length) -> bytes:
    """
    Takes an integer and returns the little-endian byte sequence
    """ 
    return n.to_bytes(length, 'little')

def read_varint(s):
    """
    Reads a variable integer from a stream
    """
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # oxff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i

def encode_varint(i):
    """
    Encodes an integer as a varint
    """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(1, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(1, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(1, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))
