"""
Script implementation
"""
from logging import Logger
from typing import List

from helper import (
    encode_varint, 
    int_to_little_endian, 
    little_endian_to_int, 
    read_varint
)
from op import OP_CODE_FUNCTIONS, OP_CODE_NAMES


LOGGER = Logger

class Script:
    """
    Defines attributes and methods of Script
    """
    def __init__(self, cmds=None) -> None:
        """
        Initialize new Script
        """
        if cmds is None:
            self.cmds: List = []
        else:
            self.cmds = cmds

    @classmethod
    def parse(cls, s):
        """
        Parse a stream
        """
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]

            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n

            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1

            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2

            else:
                op_code = current_byte
                cmds.append(op_code)

        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        """
        Serialize a raw script
        """
        result = b''

        for cmd in self.cmds:
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)

            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                
                elif length > 75 and length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                
                elif length >= 0x100 and length <=520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)

                else:
                    raise ValueError('too long an cmd')
                result += cmd

        return result

    def serialize(self):
        """
        Serialize a script
        """
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def __add__(self, other):
        """
        Combine two command sets to create a new Script object
        """
        return Script(self.cmds + other.cmds)

    def evaluate(self, z) -> bool:
        """
        Evaluates Script
        """
        cmds = self.cmds[:]
        stack = []
        altstack = []

        while len(cmds) > 0:
            cmd = cmds.pop(0)

            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False
                
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False

                elif cmd in (172, 173, 274, 175):
                    if not operation(stack, z):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False

                else:
                    if not operation(stack):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False

            else:
                stack.append(cmd)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True
                        