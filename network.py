"""
Network Implementation
"""
from io import BytesIO
from random import randint
import socket
import time
from typing import List, Union
from typing_extensions import Self

from helper import (
    encode_varint, 
    hash256, 
    int_to_little_endian, 
    little_endian_to_int, 
    read_varint
)
from block import Block


TESTNET_NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class NetworkEnvelope:
    """
    
    """
    def __init__(self, command, payload, testnet=False) -> None:
        """
        Instantiates a new network envelope
        """
        self.command = command
        self.paylaod = payload

        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self) -> str:
        """
        String representation of NetworkEnvelope object
        """
        return f'{self.command.decode("ascii")}: {self.paylaod.hex()}'

    @classmethod
    def parse(cls, s: BytesIO, testnet=False):
        """
        Parse network message to NetworkEnvelope object
        """
        magic = s.read(4)
        if magic == b'':
            raise IOError('Connection reset!')
        
        if testnet:
            expected_magic = NETWORK_MAGIC
        else:
            expected_magic = TESTNET_NETWORK_MAGIC

        if magic != expected_magic:
            raise SyntaxError(f'magic is not right {magic.hex()} vs {expected_magic.hex()}')

        command = s.read(12)
        command = command.strip(b'\x00')

        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)
        calculated_checksum = hash256(payload_length)[:4]

        if calculated_checksum != checksum:
            raise IOError("checksum does not match")

        return cls(command, payload, testnet=testnet)

    def serialize(self):
        """
        Serialize a NetworkEnvelope object to a stream
        """
        result = self.magic
        result += self.command + b'\x00' * (12 - len(self.command))
        result += int_to_little_endian(len(self.paylaod), 4)
        result += hash256(self.paylaod)[:4]
        result += self.paylaod

        return result


class VersionMessage:
    command = b'version'

    def __init__(
        self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b'\x00\x00\x00\x00',
        receiver_port=8333,
        sender_services=0,
        sender_ip=b'\x00\x00\x00\x00',
        sender_port=8333,
        nonce=None,
        user_agent=b'/programmingbitcoin:0.1/',
        latest_block=0,
        relay=False
    ) -> None:
        """
        Instantiates a new version message
        """
        self.version = version
        self.services = services
        
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port

        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2 ** 64), 8)
        else:
            self.nonce = nonce

        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        """
        Serializes a version message object
        """
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)
        result += int_to_little_endian(self.receiver_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        result += int_to_little_endian(self.receiver_port, 2)
        result += int_to_little_endian(self.sender_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        result += int_to_little_endian(self.sender_port)
        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += int_to_little_endian(self.latest_block, 4)

        if self.relay:
            relay += b'\x01'
        else:
            result += b'\x00'

        return result


class VerAckMessage:
    command = b'verack'

    def __init__(self) -> None:
        pass

    @classmethod
    def parse(cls, s):
        """
        """
        return cls()

    def serialize(self):
        """
        """
        return b''


class SimpleNode:
    def __init__(self, host, port=None, testnet=False, logging=False) -> None:
        """
        Instantiates a simple node
        """
        if port is None:
            if testnet:
                port = 8333
            else:
                port = 8333

        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb', None)

    def send(self, message: Union[VerAckMessage, VersionMessage]):
        """
        Sends a message to the connected node
        """
        envelope = NetworkEnvelope(
            message.command,
            message.serialize(),
            testnet=self.testnet
        )

        if self.logging:
            print(f'sending: {envelope}')

        self.socket.sendall(envelope.serialize())

    def read(self):
        """
        Reads a message from the socket
        """
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)

        if self.logging:
            print(f'receiving: {envelope}')

        return envelope

    def wait_for(self, *message_classes):
        """
        Wait for one of the messages in the list
        """
        command = None
        command_to_class = {m.command: m for m in message_classes}

        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command

            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.paylaod))

        return command_to_class[command].parse(envelope.stream())

    def handshake(self):
        version = VersionMessage()
        self.send(version)
        self.wait_for(VerAckMessage)


class PingMessage:
    command = b'ping'

    def __init__(self, nonce) -> None:
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce) -> None:
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None) -> None:
        """
        Instantiates new GetHeadersMessage object
        """
        self.version = version
        self.num_hashes = num_hashes

        if start_block is None:
            raise RuntimeError('a start block is required')

        self.start_block = start_block

        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks) -> None:
        """
        
        """
        self.blocks = blocks

    @classmethod
    def parse(cls, stream: BytesIO):
        """
        Parse headers message
        """
        num_headers = read_varint(stream)
        blocks = []

        for _ in range(num_headers):
            blocks.append(Block.parse(stream))
            num_txs = read_varint(stream)
            if num_txs != 0:
                raise RuntimeError('number of txs not 0')
        
        return cls(blocks)


class GenericMessage:
    def __init__(self, command, payload) -> Self:
        """
        Instantiates a generic message
        """
        self.command = command
        self.payload = payload

    def serialize(self):
        return self.payload


class GetDataMessage:
    command = b'getdata'

    def __init__(self) -> None:
        self.data: List = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):
        result = encode_varint(len(self.data))
        for data_type, identifier in self.data:
            result += int_to_little_endian(data_type, 4)
            result += identifier[::-1]

        return result
        