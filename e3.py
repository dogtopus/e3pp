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

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import bytes_to_long

def locate_key(fw):
    # RSA public exponent is a very good signature for locating key blocks.
    PATTERN = b'\x00' * 0xfd + b'\x01\x00\x01'
    offset = fw.find(PATTERN)
    offset -= 0x110
    return offset

def parse_and_extract_key(fw, offset, prefix=None):
    print(f'Serial: {fw[offset:offset+0x10].hex()}')
    offset_sig = offset + 0x210
    offset_private = offset + 0x310
    offset_end = offset_private + 0x280
    n = bytes_to_long(fw[offset+0x10:offset+0x110])
    e = bytes_to_long(fw[offset+0x110:offset+0x210])
    p = bytes_to_long(fw[offset_private:offset_private+0x80])
    q = bytes_to_long(fw[offset_private+0x80:offset_private+0x100])
    d = Integer(e).inverse((p-1) * (q-1))

    keypair = RSA.construct((n, e, d, p, q))
    pub_der = keypair.publickey().exportKey('DER')
    print(f'Fingerprint: {SHA256.new(pub_der).hexdigest()}')

    if prefix is not None:
        print('Dumping keys')
        with open(f'{prefix}.ds4id', 'wb') as f:
            f.write(fw[offset:offset_sig])
        with open(f'{prefix}.ds4id.sig', 'wb') as f:
            f.write(fw[offset_sig:offset_private])
        with open(f'{prefix}.ds4key', 'wb') as f:
            f.write(fw[offset:offset_end])
        with open(f'{prefix}-keypair.der', 'wb') as f:
            f.write(keypair.exportKey('DER'))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} file-contains-ds4key [output-prefix]')
        sys.exit(1)

    output_prefix = None if len(sys.argv) < 3 else sys.argv[2]
    with open(sys.argv[1], 'rb') as f:
        fw = f.read()
    key_offset = locate_key(fw)
    if key_offset < 0:
        print('Cannot locate keys.')
        sys.exit(1)
    else:
        print(f'Found identity block @ 0x{key_offset:x}')
        parse_and_extract_key(fw, key_offset, output_prefix)
