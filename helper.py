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