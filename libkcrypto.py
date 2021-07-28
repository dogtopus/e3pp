#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

'''
Next generation "a certain game controller OEM" crypto library.

Implements encryption and decryption using the algorithm described
by oct0xor. The writeup by him can be fount at https://bit.ly/374dkfI.

WARNING: For people who wants a general propose cipher: DO NOT USE THIS!
The algorithm implemented here is INSANELY INSECURE. DO NOT use it in a
production environment where you value your data confidentiality by even
just a tiny bit. I'm not responsible for any potential data breaches
caused by using this library in production.
'''

from typing import (
    Callable,
    NamedTuple,
    Dict,
    Sequence,
    Literal,
    Union,
    Iterator,
    Tuple,
)

import itertools
import io


def swap(n: int) -> int:
    '''
    Swap the high and low 16-bits of a 32-bit unsigned integer.
    '''
    hi = (n >> 16) & 0xffff
    lo = n & 0xffff
    return (lo << 16) | hi


BKMethodCallback = Callable[[int, int], int]


class BKMethod(NamedTuple):
    dec: BKMethodCallback
    enc: BKMethodCallback
    key: BKMethodCallback


BK_METHODS: Dict[str, BKMethod] = {
    'sub': BKMethod(
        lambda k, ct: (k - ct) & 0xffffffff,
        lambda k, pt: (k - pt) & 0xffffffff,
        lambda ct, pt: (ct + pt) & 0xffffffff,
    ),
    'subr': BKMethod(
        lambda k, ct: (ct - k) & 0xffffffff,
        lambda k, pt: (pt + k) & 0xffffffff,
        lambda ct, pt: (ct - pt) & 0xffffffff,
    ),
    'xor': BKMethod(
        lambda k, ct: k ^ ct,
        lambda k, pt: k ^ pt,
        lambda ct, pt: ct ^ pt,
    ),
    'bsub': BKMethod(
        lambda k, ct: (swap(k) - ct) & 0xffffffff,
        lambda k, pt: (swap(k) - pt) & 0xffffffff,
        lambda ct, pt: swap((ct + pt) & 0xffffffff),
    ),
    'bsubr': BKMethod(
        lambda k, ct: (ct - swap(k)) & 0xffffffff,
        lambda k, pt: (pt + swap(k)) & 0xffffffff,
        lambda ct, pt: swap((ct - pt) & 0xffffffff),
    ),
    'bxor': BKMethod(
        lambda k, ct: swap(k) ^ ct,
        lambda k, pt: swap(k) ^ pt,
        lambda ct, pt: swap(ct ^ pt),
    ),
}


# Single block API
def block_dec(key: int, ciphertext: int, method: str) -> int:
    '''
    Decrypts a single block with the given key and method.
    '''
    return BK_METHODS[method].dec(key, ciphertext)

def block_enc(key: int, plaintext: int, method: str) -> int:
    '''
    Encrypts a single block with the given key and method.
    '''
    return BK_METHODS[method].enc(key, plaintext)

def block_diff(method: str, ciphertext_prev: int, ciphertext: int, plaintext: int) -> int:
    '''
    Calculate the key given a method, the current and previous ciphertext
    block and the plaintext block.
    '''
    return (BK_METHODS[method].key(ciphertext, plaintext) - ciphertext_prev) & 0xffffffff


def _bytes2blocks(data: Union[bytes, bytearray, memoryview], endian: str = 'little') -> Iterator[int]:
    '''
    Iterates a 32-bit aligned bytes object as 32-bit unsigned ints.
    '''
    data_iterator = iter(data)
    for i in zip(data_iterator, data_iterator, data_iterator, data_iterator):
        yield int.from_bytes(bytes(i), endian)


class BKCryptoContext:
    '''
    The context class for the cipher. Loosely modeled after pycryptodome's
    symmetric cipher contexts.
    '''
    _key: Sequence[int]
    _methods: Sequence[str]
    _iv: int
    _state: Literal['init', 'enc', 'dec']
    _cprev: int
    _kmstream: Iterator[Tuple[int, str]]

    def __init__(self, key: bytes, methods: Sequence[str], iv: int) -> None:
        '''
        Creates the context. Takes a key stream in big endian, a list of
        methods to use (choose from sub, subr, xor, bsub, bsubr and bxor)
        and the 32-bit unsigned initialization vector (IV).
        '''
        if len(key) % 4 != 0:
            raise ValueError('Key length must be a multiple of 32-bits.')
        for method in methods:
            if method not in BK_METHODS:
                raise ValueError(f'Invalid method {method}.')
        if iv & 0xffffffff != iv:
            raise ValueError('IV must be a 32-bit unsigned integer.')

        self._key = tuple(_bytes2blocks(key, 'big'))
        self._methods = methods
        self._iv = iv

        # CBC states
        self._state = 'init'
        self._cprev = self._iv
        self._kmstream = zip(itertools.cycle(self._key), itertools.cycle(self._methods))

    @staticmethod
    def _check_align_or_fail(data: Union[bytes, bytearray, memoryview]) -> None:
        if len(data) % 4 != 0:
            raise ValueError('Input data length must be a multiple of 32-bits.')

    def _convert_to(self, state: Literal['enc', 'dec']) -> None:
        assert state in ('enc', 'dec'), f'Internal inconsistency: Invalid context state {state}.'
        if self._state == 'init':
            self._state = state
        elif self._state != state:
            raise ValueError(f'Context object is already in the state {self._state}, cannot convert to {state}.')

    def _peek_key_block(self, kblk: int) -> int:
        return (self._cprev + kblk) & 0xffffffff

    def _chain_block(self, cblk: int) -> None:
        self._cprev = cblk

    def _peek_key_and_chain_block(self, kblk: int, cblk: int) -> int:
        effective_key = self._peek_key_block(kblk)
        self._chain_block(cblk)
        return effective_key

    def encrypt(self, data: Union[bytes, bytearray, memoryview]) -> bytes:
        '''
        Encrypt data. Note that the context can only be either decrypting or
        encrypting. This will be selected during the first time
        BKCryptoContext.encrypt or BKCryptoContext.decrypt gets called.
        '''
        self._convert_to('enc')
        self._check_align_or_fail(data)
        buf = io.BytesIO()

        for blk, km in zip(_bytes2blocks(data), self._kmstream):
            key, method = km
            effective_key = self._peek_key_block(key)
            result = block_enc(effective_key, blk, method)
            self._chain_block(result)
            buf.write(result.to_bytes(4, 'little'))

        return buf.getvalue()

    def decrypt(self, data: Union[bytes, bytearray, memoryview]) -> bytes:
        '''
        Decrypt data. Note that the context can only be either decrypting or
        encrypting. This will be selected during the first time
        BKCryptoContext.encrypt or BKCryptoContext.decrypt gets called.
        '''
        self._convert_to('dec')
        self._check_align_or_fail(data)
        buf = io.BytesIO()

        for blk, km in zip(_bytes2blocks(data), self._kmstream):
            key, method = km
            effective_key = self._peek_key_and_chain_block(key, blk)
            result = block_dec(effective_key, blk, method)
            buf.write(result.to_bytes(4, 'little'))

        return buf.getvalue()

# TODO Forensics context for dumping decryption results with all methods.
