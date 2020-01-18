#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense
# Embrace, extend, extinguish, now with Super Cow Powers
#
# Provides tools for easier manual key extraction, also decrypts firmware
# images using the user-specified key configuration file.
# Works with firmware update images for controllers manufactured by a certain
# OEM.
#
# Based on the algorithm and weakness documented by oct0xor
# https://securelist.com/hacking-microcontroller-firmware-through-a-usb/89919/

import click
import yaml
import sys
import functools
import codecs
import typing as T
import copy
from collections import Counter

yaml.load = functools.partial(yaml.load, Loader=yaml.SafeLoader)

BKMethodCallback = T.Callable[[int, int], int]


class BKMethod(T.NamedTuple):
    dec: BKMethodCallback
    enc: BKMethodCallback
    key: BKMethodCallback


def swap(n: int) -> int:
    hi = (n >> 16) & 0xffff
    lo = n & 0xffff
    return (lo << 16) | hi

bk_methods: T.Dict[str, BKMethod] = {
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

DEFAULT_IV = 0xda872d01

def bk_block_dec(key: int, ciphertext: int, method: str) -> int:
    return bk_methods[method].dec(key, ciphertext)

def bk_block_enc(key: int, plaintext: int, method: str) -> int:
    return bk_methods[method].enc(key, plaintext)

def bk_diff(method: str, ciphertext_prev: int, ciphertext: int, plaintext: int) -> int:
    return (bk_methods[method].key(ciphertext, plaintext) - ciphertext_prev) & 0xffffffff

def load_key_config(stream: T.TextIO) -> T.Dict[str, T.Any]:
    config = yaml.load(stream)
    if isinstance(config['keystream'], str):
        config['keystream'] = config['keystream'].encode('ascii')
    return config


BlockDecryptionResult = T.Dict[str, int]

def dec_all_method(keystream: bytes, iv: int, ciphertext: T.BinaryIO) -> T.Iterable[BlockDecryptionResult]:
    keystream_size = len(keystream)
    if keystream_size % 4 != 0:
        raise ValueError('length of the key stream must be divisible by 4')
    key_stream_mv = memoryview(keystream)
    cprev = iv
    nk = keystream_size // 4
    kindex = 0
    blk = bytearray(4)
    while ciphertext.readinto(blk) != 0:
        k = int.from_bytes(key_stream_mv[4*kindex:4*(kindex+1)], 'big')
        k = (k + cprev) & 0xffffffff
        c = int.from_bytes(blk, 'little')
        result = {method: bk_block_dec(k, c, method) for method in bk_methods.keys()}
        yield result
        kindex += 1
        kindex %= nk
        cprev = c


class BlockMatcher(object):
    def update_block(self, block: BlockDecryptionResult) -> None:
        '''
        Update the mapping with new data enclosed in a BlockDecryptionResult.
        '''
        raise NotImplemented()

    def get_result(self) -> T.Dict[int, str]:
        '''
        Read out the block-to-method mapping result.
        '''
        raise NotImplemented()


class CommonBlockMatcher(BlockMatcher):
    '''
    Finds the most commonly occurred value in a specific region of blocks and return all offsets
    that point to this value. Useful for uncovering a big chunk of the method chain by searching
    the NVIC table for the null interrupt handler.
    '''
    def __init__(self, block_range: T.Tuple[int, int], assume_sign: str) -> None:
        # *r methods generate a negative version of the plaintext which might interfere with the result. So we need to assume the sign.
        # For NVIC this is perfectly fine since vectors usually points to flash and sometimes SRAM, which all have "positive" offsets at least for nuvoton.
        _sign: Dict[str, T.Callable[[int], bool]] = {
            'positive': (lambda x: not ((x >> 31) & 1)),
            'negative': (lambda x: (x >> 31) & 1),
            'dontcare': (lambda _: True)
        }
        self.begin = block_range[0]
        self.end = block_range[1]
        self.block_offset = 0
        self.ctr = Counter()
        # dec_value: {offset, method}
        self.scratch_pad: T.Dict[int, T.Dict[int, str]] = {}
        self.zero_blocks: T.Dict[int, str] = {}
        self._sign = _sign[assume_sign]

    def update_block(self, block: BlockDecryptionResult) -> None:
        if self.begin <= self.block_offset < self.end:
            zero = (block['sub'] == 0 and block['subr'] == 0 and block['xor'] == 0)
            bzero = (block['bsub'] == 0 and block['bsubr'] == 0 and block['bxor'] == 0)
            if zero or bzero:
                self.zero_blocks[self.block_offset] = 'b*' if zero else '~b*'
            else:
                for method, val in block.items():
                    issub = method.find('sub') >= 0
                    if (issub and self._sign(val)) or not issub:
                        self.ctr[val] += 1
                        if val not in self.scratch_pad:
                            self.scratch_pad[val] = {}
                        self.scratch_pad[val][self.block_offset] = method
        self.block_offset += 4

    def get_result(self) -> T.Dict[int, str]:
        most_common_val = self.ctr.most_common(1)[0][0]
        result = copy.copy(self.scratch_pad[most_common_val])
        result.update(self.zero_blocks)
        return result


@click.group()
def main():
    pass

@main.command('diff', help='Try to print the key blocks used to encrypt given plaintext to given ciphertext.')
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.argument('plaintext', type=click.File('rb'), required=True)
@click.option('--iv', help='Specify an initialization vector', default=DEFAULT_IV, show_default=True)
def do_diff(ciphertext: T.BinaryIO, plaintext: T.BinaryIO, iv: int) -> None:
    cprev = iv
    while True:
        c = ciphertext.read(4)
        p = plaintext.read(4)
        if c is None or p is None or len(c) != 4 or len(p) != 4:
            break
        c = int.from_bytes(c, 'little')
        p = int.from_bytes(p, 'little')
        result = tuple(f'{method}:{repr(bk_diff(method, cprev, c, p).to_bytes(4, "big"))}' for method in bk_methods.keys())
        click.echo(', '.join(result))
        cprev = c

@main.command('guesskey', help='Guess the key by assuming every block decrypts to 0.')
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.option('-d', '--dump-decryption-result', is_flag=True, help='Output decryption result to stdout')
@click.option('-s', '--guess-keystream-size', default=9, type=int, show_default=True, help='Guess key stream size (in blocks)')
def do_guesskey(ciphertext: T.BinaryIO, dump_decryption_result: bool, guess_keystream_size: int) -> None:
    counts = list(Counter() for _ in range(guess_keystream_size))
    cprev = 0
    kspos = 0
    while True:
        c = ciphertext.read(4)
        if c is None or len(c) != 4:
            break
        c = int.from_bytes(c, 'little')
        result = [] if dump_decryption_result else None
        for method in bk_methods.keys():
            dec = bk_diff(method, cprev, c, 0x0).to_bytes(4, "big")
            counts[kspos][dec] += 1
            if dump_decryption_result:
                result.append(f'{method}:{repr(dec)}')
        if dump_decryption_result:
            click.echo(', '.join(result))
        cprev = c
        kspos += 1
        kspos %= guess_keystream_size
    click.echo('Frequency statistics (top 5 for each block):')
    possible_key = []
    for b, count in enumerate(counts):
        click.echo(f'keystream block {b}:')
        for e in count.most_common(5):
            click.echo(f'  {repr(e[0])}: {e[1]}')
        max_count = None
        for e in count.most_common(1):
            possible_key.append(e[0])
    possible_key = b''.join(possible_key)
    click.echo(f'Possible key: {repr(possible_key)} (base64:{codecs.encode(possible_key, "base64").decode("ascii").strip()})')

@main.command('guessmethod')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.argument('pattern-file', type=click.File('r'), required=True)
@click.option('-l', '--max-chain-length', type=int, default=16, show_default=True, help='Set the maximum assumed chain length.')
def do_guessmethod(config_file: T.TextIO, ciphertext: T.BinaryIO, pattern_file: T.TextIO, max_chain_length: int) -> None:
    """
    Guess the method chain using known key stream and plaintext patterns.
    """
    config = load_key_config(config_file)
    patterns: dict = yaml.load(pattern_file)
    matchers: List[BlockMatcher] = []
    # TODO
    for name, params in patterns.items():
        pattern_type: str = params['type']
        if 'type' not in params:
            raise ValueError(f'Invalid rule {name}. Type entry is missing.')
        click.echo(f'Found rule "{name}" with type {params["type"]}')
        # Add matchers by expanding this if block
        if pattern_type == 'common_block':
            matchers.append(CommonBlockMatcher(params['range'], params['assume_sign']))
        else:
            click.echo(f'Skipping unsupported rule "{name}"')
    # counting
    for block in dec_all_method(config['keystream'], config['iv'], ciphertext):
        for m in matchers:
            m.update_block(block)

    # DEBUG print all raw results
    for m in matchers:
        click.echo(m.get_result())

    max_ratio = 0
    max_zratio = 0
    max_chain = None
    # analyze the data
    for chain_len in range(1, max_chain_length):
        buckets = [Counter() for _ in range(chain_len)]
        zero_buckets = [Counter() for _ in range(chain_len)]
        for m in matchers:
            for byte_offset, val in m.get_result().items():
                block_offset = byte_offset // 4
                if val not in ('b*', '~b*'):
                    bucket = buckets[block_offset % chain_len]
                    bucket[val] += 1
                else:
                    zero_bucket = zero_buckets[block_offset % chain_len]
                    zero_bucket[val] += 1
        total_samples = sum(sum(b.values()) for b in buckets)
        total_zsamples = sum(sum(b.values()) for b in zero_buckets)
        max_samples = 0
        max_zsamples = 0
        for b, zb in zip(buckets, zero_buckets):
            max_count = b.most_common(1)
            max_zcount = zb.most_common(1)
            if len(max_count) == 0:
                continue
            else:
                max_samples += max_count[0][1]
            if len(max_zcount) == 0:
                continue
            else:
                max_zsamples += max_zcount[0][1]
        ratio = max_samples / total_samples
        zratio = max_zsamples / total_zsamples
        chain = []
        # Read the chain
        for b in buckets:
            max_count = b.most_common(1)
            if len(max_count) == 0:
                chain.append(None)
            else:
                chain.append(max_count[0][0])
        # Print local stats
        click.echo(f'Chain length of {chain_len}: {max_samples} out of {total_samples} samples fit. Fitness ratio {ratio*100}%.')
        click.echo(f'Chain length of {chain_len}: {max_zsamples} out of {total_zsamples} zero block samples are consistent. Consistency {zratio*100}%.')
        # Save the current maximum chain
        if ratio >= max_ratio:
            max_ratio = ratio
            max_zratio = zratio
            max_chain = chain
        # Stop searching if we got a perfect match
        if max_samples == total_samples:
            click.echo(f'Found perfect match. Stop searching.')
            break
    click.echo(f'Found best maching chain {max_chain} with fitness ratio of {max_ratio*100}% and zero block consistency of {max_zratio*100}%.')
    if None in max_chain:
        click.echo(f'WARNING: Chain incomplete. You should rerun this with more matching patterns added.')

@main.command('dec-nochain')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('ciphertext', type=click.File('rb'), required=True)
def do_dec_all_use_all_methods(config_file: T.TextIO, ciphertext: T.BinaryIO) -> None:
    """
    Print all possible decryption results of ciphertext using key specified in config-file and **all supported methods**.
    """
    config = load_key_config(config_file)
    for result in dec_all_method(config['keystream'], config['iv'], ciphertext):
        click.echo(', '.join(f'{method}:{plaintext:08x}' for method, plaintext in result.items()))

@main.command('dec')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.argument('output', type=click.File('wb'), required=True)
def do_dec(config_file: T.TextIO, ciphertext: T.BinaryIO, output: T.BinaryIO) -> None:
    """
    Decrypt CIPHERTEXT using the key and method chain specified in CONFIG-FILE and write the result to OUTPUT.
    """
    config = load_key_config(config_file)
    key_stream = config['keystream']
    chain = config['chain']
    key_stream_mv = memoryview(key_stream)
    cprev = config['iv']
    if len(key_stream) % 4 != 0:
        raise ValueError('length of the key stream must be divisible by 4')
    nk = len(key_stream) // 4
    nm = len(chain)
    kindex = 0
    mindex = 0
    blk = bytearray(4)
    while ciphertext.readinto(blk) != 0:
        k = int.from_bytes(key_stream_mv[4*kindex:4*(kindex+1)], 'big')
        k = (k + cprev) & 0xffffffff
        c = int.from_bytes(blk, 'little')
        method = chain[mindex]
        result = bk_block_dec(k, c, method)
        output.write(result.to_bytes(4, 'little'))
        kindex += 1
        kindex %= nk
        mindex += 1
        mindex %= nm
        cprev = c

@main.command('enc')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('plaintext', type=click.File('rb'), required=True)
@click.argument('output', type=click.File('wb'), required=True)
def do_enc(config_file: T.TextIO, plaintext: T.BinaryIO, output: T.BinaryIO) -> None:
    """
    Similar to dec but encrypts PLAINTEXT.
    """
    config = load_key_config(config_file)
    key_stream = config['keystream']
    chain = config['chain']
    key_stream_mv = memoryview(key_stream)
    cprev = config['iv']
    if len(key_stream) % 4 != 0:
        raise ValueError('length of the key stream must be divisible by 4')
    nk = len(key_stream) // 4
    nm = len(chain)
    kindex = 0
    mindex = 0
    blk = bytearray(4)
    while plaintext.readinto(blk) != 0:
        k = int.from_bytes(key_stream_mv[4*kindex:4*(kindex+1)], 'big')
        k = (k + cprev) & 0xffffffff
        p = int.from_bytes(blk, 'little')
        method = chain[mindex]
        result = bk_block_enc(k, p, method)
        output.write(result.to_bytes(4, 'little'))
        kindex += 1
        kindex %= nk
        mindex += 1
        mindex %= nm
        cprev = result

if __name__ == '__main__':
    main()
