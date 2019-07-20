#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense
# Embrace, extend, extinguish, now with Super Cow Powers
#
# Provides tools for easier manual key extraction, also decrypts firmware
# images using the user-specified key configuration file.
# Works with firmware update images for controllers manufactured by a certain
# OEM.
#
# A implementation of the attack documented on
# https://securelist.com/hacking-microcontroller-firmware-through-a-usb/89919/

import click
import yaml
import sys
import functools
from collections import namedtuple, Counter

yaml.load = functools.partial(yaml.load, Loader=yaml.SafeLoader)

BKPrimitive = namedtuple('BKPrimitive', ('dec', 'enc', 'key'))

def swap(n):
    hi = (n >> 16) & 0xffff
    lo = n & 0xffff
    return (lo << 16) | hi

bk_primitives = {
    'sub': BKPrimitive(
        lambda k, ct: (k - ct) & 0xffffffff,
        lambda k, pt: (k - pt) & 0xffffffff,
        lambda ct, pt: (ct + pt) & 0xffffffff,
    ),
    'subr': BKPrimitive(
        lambda k, ct: (ct - k) & 0xffffffff,
        lambda k, pt: (pt + k) & 0xffffffff,
        lambda ct, pt: (ct - pt) & 0xffffffff,
    ),
    'xor': BKPrimitive(
        lambda k, ct: k ^ ct,
        lambda k, pt: k ^ pt,
        lambda ct, pt: ct ^ pt,
    ),
    'bsub': BKPrimitive(
        lambda k, ct: (swap(k) - ct) & 0xffffffff,
        lambda k, pt: (swap(k) - pt) & 0xffffffff,
        lambda ct, pt: swap((ct + pt) & 0xffffffff),
    ),
    'bsubr': BKPrimitive(
        lambda k, ct: (ct - swap(k)) & 0xffffffff,
        lambda k, pt: (pt + swap(k)) & 0xffffffff,
        lambda ct, pt: swap((ct - pt) & 0xffffffff),
    ),
    'bxor': BKPrimitive(
        lambda k, ct: swap(k) ^ ct,
        lambda k, pt: swap(k) ^ pt,
        lambda ct, pt: swap(ct ^ pt),
    ),
}

DEFAULT_IV = 0xda872d01

def bk_block_dec(key, ciphertext, method):
    return bk_primitives[method].dec(key, ciphertext)

def bk_block_enc(key, plaintext, method):
    return bk_primitives[method].enc(key, plaintext)

def bk_diff(method, ciphertext_prev, ciphertext, plaintext):
    return (bk_primitives[method].key(ciphertext, plaintext) - ciphertext_prev) & 0xffffffff

@click.group()
def main():
    pass

@main.command('diff', help='Try to print the key blocks used to encrypt given plaintext to given ciphertext.')
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.argument('plaintext', type=click.File('rb'), required=True)
@click.option('--iv', help='Specify an initialization vector (default is 0xda872d01)', default=DEFAULT_IV)
def do_diff(ciphertext, plaintext, iv):
    cprev = iv
    while True:
        c = ciphertext.read(4)
        p = plaintext.read(4)
        if c is None or p is None or len(c) != 4 or len(p) != 4:
            break
        c = int.from_bytes(c, 'little')
        p = int.from_bytes(p, 'little')
        result = tuple(f'{method}:{repr(bk_diff(method, cprev, c, p).to_bytes(4, "big"))}' for method in bk_primitives.keys())
        click.echo(', '.join(result))
        cprev = c

@main.command('diff0', help='Similar to diff but assume the plaintext is all 0.')
@click.argument('ciphertext', type=click.File('rb'), required=True)
def do_diff0(ciphertext):
    count = Counter()
    cprev = 0
    while True:
        c = ciphertext.read(4)
        if c is None or len(c) != 4:
            break
        c = int.from_bytes(c, 'little')
        result = []
        for method in bk_primitives.keys():
            dec = bk_diff(method, cprev, c, 0x0).to_bytes(4, "big")
            count[dec] += 1
            result.append(f'{method}:{repr(dec)}')
        click.echo(', '.join(result))
        cprev = c
    click.echo('Frequency statistics (top 50):')
    for e in count.most_common(50):
        click.echo(f'{repr(e[0])}: {e[1]}')

@main.command('dec-nochain')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('ciphertext', type=click.File('rb'), required=True)
def do_dec_all_use_all_methods(config_file, ciphertext):
    """
    Print all possible decryption results of ciphertext using key specified in config-file **all supported methods**.
    """
    config = yaml.load(config_file)
    key_stream_mv = memoryview(config['keystream'])
    cprev = config['iv']
    keystream_size = len(config['keystream'])
    if keystream_size % 4 != 0:
        raise ValueError('length of the key stream must be divisible by 4')
    nk = keystream_size // 4
    kindex = 0
    blk = bytearray(4)
    while ciphertext.readinto(blk) != 0:
        k = int.from_bytes(key_stream_mv[4*kindex:4*(kindex+1)], 'big')
        k = (k + cprev) & 0xffffffff
        c = int.from_bytes(blk, 'little')
        result = tuple(f'{method}:{bk_block_dec(k, c, method):08x}' for method in bk_primitives.keys())
        click.echo(', '.join(result))
        kindex += 1
        kindex %= nk
        cprev = c

@main.command('dec')
@click.argument('config-file', type=click.File('r'), required=True)
@click.argument('ciphertext', type=click.File('rb'), required=True)
@click.argument('output', type=click.File('wb'), required=True)
def do_dec_all(config_file, ciphertext, output):
    """
    Decrypt CIPHERTEXT using the key and method chain specified in CONFIG-FILE and write the result to OUTPUT.
    """
    config = yaml.load(config_file)
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

if __name__ == '__main__':
    main()
