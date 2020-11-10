#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense
# Embrace, extend, extinguish
#
# Dumps information of a DS4 key block and (optionally) extracts it from
# a binary file. Also works with raw key blocks extracted by
# e.g. jedi_crypto.py.
#
# Extracts the untouched key block (identity block + private key block),
# identity block (serial number + public key block + signature)
# and the identity key-pair in DER format.

import sys
import argparse
import functools
import traceback

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import bytes_to_long

def locate_key(fw, e_padding_size=0xfc):
    # RSA public exponent is a very good signature for locating key blocks.
    PATTERN = b'\x00' * e_padding_size + b'\x00\x01\x00\x01'
    offset = fw.find(PATTERN)
    offset -= 0x110
    return offset

def parse_and_extract_key(fw, offset, e_padding_size=0xfc, prefix=None):
    print(f'Serial: {fw[offset:offset+0x10].hex()}')
    offset_sig = offset + 0x110 + e_padding_size + 4
    offset_private = offset + 0x210 + e_padding_size + 4
    offset_end = offset_private + 0x280
    n = bytes_to_long(fw[offset+0x10:offset+0x110])
    e = bytes_to_long(fw[offset+0x110:offset+0x110+e_padding_size+4])
    p = bytes_to_long(fw[offset_private:offset_private+0x80])
    q = bytes_to_long(fw[offset_private+0x80:offset_private+0x100])
    dp1 = bytes_to_long(fw[offset_private+0x100:offset_private+0x180])
    dq1 = bytes_to_long(fw[offset_private+0x180:offset_private+0x200])
    pq = bytes_to_long(fw[offset_private+0x200:offset_private+0x280])
    d = Integer(e).inverse((p-1) * (q-1))
    pq_from_pq = Integer(q).inverse(p)
    dp1_from_pq = Integer(d) % (p-1)
    dq1_from_pq = Integer(d) % (q-1)
    if Integer(pq) != pq_from_pq or Integer(dp1) != dp1_from_pq or Integer(dq1) != dq1_from_pq:
        raise ValueError('Bad key block (CRT factors inconsistent with P and Q)')

    keypair = RSA.construct((n, e, d, p, q))
    pub_der = keypair.publickey().exportKey('DER')
    print(f'Fingerprint: {SHA256.new(pub_der).hexdigest()}')

    if prefix is not None:
        print('Dumping keys')
        with open(f'{prefix}.ds4id', 'wb') as f:
            f.write(fw[offset:offset+0x10])
            f.write(n.to_bytes(0x100, 'big'))
            f.write(e.to_bytes(0x100, 'big'))
        with open(f'{prefix}.ds4id.sig', 'wb') as f:
            f.write(fw[offset_sig:offset_private])
        with open(f'{prefix}.ds4key', 'wb') as f:
            f.write(fw[offset:offset+0x10])
            f.write(n.to_bytes(0x100, 'big'))
            f.write(e.to_bytes(0x100, 'big'))
            f.write(fw[offset_sig:offset_private])
            f.write(fw[offset_private:offset_end])
        with open(f'{prefix}-keypair.der', 'wb') as f:
            f.write(keypair.exportKey('DER'))

anybase = functools.partial(int, base=0)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('file_contains_ds4key', help='Path to a file that contains the DS4Key.')
    p.add_argument('-o', '--output-prefix', help='Prefix of output file.')
    p.add_argument('-p', '--e-padding-size', type=anybase, default=0xfc, help='Padding size for exponent assuming 32-bit usable exponent (default: 0xfc).')
    return p, p.parse_args()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} file-contains-ds4key [output-prefix] [e-padding-size]')
        sys.exit(1)

    p, args = parse_args()
    ds4key_len = 0x490 + args.e_padding_size + 4

    with open(sys.argv[1], 'rb') as f:
        fw = f.read()

    key_abs_offset = 0
    while True:
        key_rel_offset = locate_key(fw, args.e_padding_size)
        if key_rel_offset < 0:
            print('No more keys found.')
            break
        key_abs_offset += key_rel_offset
        print(f'Found identity block @ 0x{key_abs_offset:x}')
        output_prefix_offset = f'{args.output_prefix}_0x{key_abs_offset:x}' if args.output_prefix is not None else None
        try:
            parse_and_extract_key(fw, key_rel_offset, args.e_padding_size, output_prefix_offset)
        except Exception as e:
            print(f'Unable to extract identity block @ 0x{key_abs_offset:x}: {str(e)}')
            traceback.print_exc()
        key_abs_offset += ds4key_len
        fw = fw[key_rel_offset+ds4key_len:]
