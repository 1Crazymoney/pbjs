"""
Operation Codes (Opcodes)
"""
from helper import hash256, hash160, encode_num, decode_num
from ecc import S256Point, Signature

def op_dup(stack) -> bool:
    """
    Duplicates an element on the stack
    """
    if len(stack) < 1:
        return False

    stack.append(stack[-1])
    return True

def op_hash256(stack) -> bool:
    """
    Performs two rounds of sha256
    """
    if len(stack) < 1:
        return False

    element = stack.pop()
    stack.append(hash256(element))
    return True

def op_hash160(stack) -> bool:
    """
    Performs SHA256 followed by RIPEMD160
    """
    if len(stack) < 1:
        return False

    element = stack.pop()
    stack.append(hash160(element))
    return True

def op_0(stack):
    """
    Append 0, i.e. b'', to the stack
    """
    stack.append(encode_num(0))
    return True

def op_checksig(stack, z) -> bool:
    """
    Operation Check Signature
    """
    if len(stack) < 2:
        return False

    sec_pubkey = stack.pop()
    der_signature = stack.pop()[:-1]

    try:
        point = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_signature)

    except (ValueError, SyntaxError) as e:
        return False

    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


OP_CODE_FUNCTIONS = {
    118: op_dup,  # 0x76
    170: op_hash256, 
    169: op_hash160,  #0xa9
}

OP_CODE_NAMES = {
    0: 'OP_0',
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    130: 'OP_SIZE',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}