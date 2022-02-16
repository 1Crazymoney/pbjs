from io import BytesIO
from typing import List
from typing_extensions import Self
import requests

from helper import (
    encode_varint, 
    hash256, 
    int_to_little_endian, 
    little_endian_to_int, 
    read_varint,
    SIGHASH_ALL
)
from script import Script
from ecc import PrivateKey



class Tx:
    """
    Defines a bitcoin transaction
    """
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False) -> "Tx":
        """
        Initializes a transaction
        """
        self.version = version
        self.tx_ins: List[TxIn] = tx_ins
        self.tx_outs: List[TxOut] = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self) -> str:
        """
        String representation of a transaction
        """
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr() + '\n'

        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'

        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        """
        Human-readable hexadecimal of the transaction hash
        """
        return self.hash().hex()

    def hash(self):
        """
        Binary hash of the legacy serialization
        """
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, stream, testnet=False) -> "Tx":
        """
        Parse a stream of transaction
        """
        version = little_endian_to_int(stream.read(4))

        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))

        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))

        locktime = little_endian_to_int(stream.read(4))

        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self):
        """
        Returns the byte serialization of the transaction
        """
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()

        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        """
        Calculates the transaction fee in satoshi
        """
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)

        for tx_out in self.tx_outs:
            output_sum += tx_out.amount

        return input_sum - output_sum

    def sig_hash(self, input_index):
        """
        Compute the signature hash for a transaction
        """
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=tx_in.script_pubkey(self.testnet),
                    sequence=tx_in.sequqnce
                ).serialize()
            else:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    sequence=tx_in.sequqnce
                ).serialize()

        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()

        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, 'big')

    def verify_input(self, input_index):
        """
        Verify a transaction input
        """
        tx_in: TxIn = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        z = self.sig_hash(input_index)
        combined: Script = tx_in.script_sig + script_pubkey

        return combined.evaluate(z)

    def verify(self):
        """
        Verify this transaction
        """
        if self.fee() < 0:
            return False

        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        
        return True

    def sign_input(self, input_index: int, private_key: PrivateKey):
        """
        Signs a transaction input

        Args:
            input_index (int): the index of the transaction input
            private_key (int): private key to sign the transaction input
        """
        z = self.sig_hash(input_index=input_index)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])

        return self.verify_input(input_index)


class TxIn:
    """
    Transaction Input
    """
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff) -> Self:
        """
        Instantiates a new transaction input
        """
        self.prev_tx = prev_tx
        self.prev_index = prev_index

        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig

        self.sequence = sequence

    def __repr__(self) -> str:
        """
        String representation of a transaction
        """
        return f"{self.prev_tx.hex()}:{self.prev_index}"

    @classmethod
    def parse(cls, stream) -> "TxIn":
        """
        Takes a byte stream and parses the tx_input at the start
        Returns a TxIn 
        """
        prev_tx = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        """
        Returns the byte serialization of the transaction input
        """
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)

        return result

    def fetch_tx(self, testnet=False):
        """
        Fetches a transaction
        """
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        """
        Get the output value by looking up the transaction hash.
        Returns the amount in satoshi
        """  
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        """
        Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        """
        tx: Tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    """
    Transaction Output
    """
    def __init__(self, amount, script_pubkey) -> None:
        """
        Instantiates a new transaction output
        """
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self) -> str:
        """
        String representation of transaction output
        """
        return f'{self.amount}:{self.script_pubkey}'

    @classmethod
    def parse(cls, stream) -> Self:
        """
        Takes a byte stream and parses the tx_output at the start.
        Returns a TxOut object
        """
        amount = little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)
        return cls(amount, script_pubkey)

    def serialize(self):
        """
        Returns the byte serialization of the transaction output
        """
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


class TxFetcher:
    """
    Fetch transactions from the UTXO set
    """
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        """
        Get mainnet or testnet url
        """
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False) -> "Tx":
        """
        Fetch transactions from the UTXO set
        """
        if fresh or (tx_id not in cls.cache):
            url = f'{cls.get_url(testnet)}/tx/{tx_id}.hex'
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f'unexpected response: {response.text}')

            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)

            if tx.id() != tx_id:
                raise ValueError(f'not the same id: {tx.id()} vs {tx_id}')

            cls.cache[tx_id] = tx

        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]