"""
Helper functions for ecc.py
"""
import hashlib

from script import Script

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SIGHASH_ALL = 1


def hash256(s) -> bytes:
    """
    Performs two rounds of sha256
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


def encode_num(num) -> bytes:
    """
    Encode an integer number to bytes equivalent
    """
    if num == 0:
        return b''

    abs_num = abs(num)
    negative = num < 0
    result = bytearray()

    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8

    if result[-1] & 0x80:
        if negative:
            result.append(0x80)

        else:
            result.append(0)

    elif negative:
        result[-1] |= 0x80

    return bytes(result)

def decode_num(element) -> int:
    """
    Decode an integer from its byte equivalent
    """
    if element == b'':
        return 0

    big_endian = element[::-1]
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f

    else:
        negative = False
        result = big_endian[0]

    for c in big_endian[1:]:
        result <<= 8
        result += c

    if negative:
        return -result

    else:
        return result

def decode_base58(s):
    """
    Decodes a base58 encoded address to extract the hash of address
    """
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)

    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]

    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(f"bad address: {checksum} {hash256(combined[:-4])[:4]}")

    return combined[1:-4]

def p2pkh_script(h160):
    """
    Takes a hash160 and returns the p2pkh ScriptPubKey
    """
    return Script([0x76, 0xa9, h160, 0x88, 0xac])

def h160_to_p2pkh_address(h160: bytes, testnet=False):
    """
    Encodes a 20-byte H160 to P2PKH address
    """
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'

    return encode_base58_checksum(prefix + h160)

def h160_to_p2sh_address(h160: bytes, testnet=False):
    """
    Encodes a 20-byte H160 to P2PKH address
    """
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'

    return encode_base58_checksum(prefix + h160)