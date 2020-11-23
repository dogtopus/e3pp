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
import itertools
import io
import traceback

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import bytes_to_long

def grouper_no_padding(gen, chunk_size):
    while len(line := tuple(itertools.islice(gen, chunk_size))) != 0:
        yield line

def int2mbedmpi(number):
    def _iter(number):
        line_break_counter = 0
        while number != 0:
            yield f'0x{int(number & 0xffffffff):08x}'
            line_break_counter += 1
            number >>= 32
    return tuple(_iter(number))

def emit_c_array(elements, name, type_, static=False, const=True, chunk_size=4):
    nmemb = len(elements)
    result = io.StringIO()
    if static:
        result.write('static ')
    if const:
        result.write('const ')
    result.write(type_)
    result.write(' ')
    result.write(name)
    result.write(f'[{nmemb}] = {{\n')
    for row in grouper_no_padding(iter(elements), chunk_size):
        result.write('  ')
        result.write(', '.join(row))
        result.write(',\n')
    result.write('};\n')
    return result.getvalue()

def to_hex_str_tuple(ba):
    return tuple(f'0x{v:02x}' for v in ba)

def locate_key(fw, e_padding_size=0xfc):
    # RSA public exponent is a very good signature for locating key blocks.
    PATTERN = b'\x00' * e_padding_size + b'\x00\x01\x00\x01'
    offset = fw.find(PATTERN)
    offset -= 0x110
    return offset

def parse_and_extract_key(fw, offset, e_padding_size=0xfc, prefix=None, passinglink=False):
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
        with open(f'{prefix}.ds4ser', 'wb') as f:
            f.write(fw[offset:offset+0x10])
        with open(f'{prefix}-keypair.der', 'wb') as f:
            f.write(keypair.exportKey('DER'))
        if passinglink:
            print('Generating PassingLink DS4Key file')
            mbedmpis = {
                'n': int2mbedmpi(n),
                'e': int2mbedmpi(e),
                'd': int2mbedmpi(d),
                'p': int2mbedmpi(p),
                'q': int2mbedmpi(q),
                'dp': int2mbedmpi(dp1),
                'dq': int2mbedmpi(dq1),
                'qp': int2mbedmpi(pq),
            }
            ds4id_str = {
                'key_n': to_hex_str_tuple(n.to_bytes(0x100, 'big')),
                'key_e': to_hex_str_tuple(e.to_bytes(0x100, 'big')),
                'serial': to_hex_str_tuple(fw[offset:offset+0x10]),
                'signature': to_hex_str_tuple(fw[offset_sig:offset_private]),
            }
            with open(f'{prefix}.h', 'w') as f:
                f.write('/* Key factors as mbedTLS MPIs */\n')
                for factor, mpi in mbedmpis.items():
                    f.write(emit_c_array(mbedmpis[factor], f'_pl_ds4key_{factor}', 'mbedtls_mpi_uint', static=True))
                    f.write('\n')
                # TODO might be good to have RN here so the calculation can be sped up.

                f.write('/* Saved DS4Key mbedTLS RSA context for use without runtime key importing (saves quite a lot of RAM) */\n')
                f.write('const struct mbedtls_rsa_context __ds4_key = {\n')
                f.write('  .ver = 0,\n  .len = 256,\n')
                f.write('  .padding = MBEDTLS_RSA_PKCS_V21, .hash_id = MBEDTLS_MD_SHA256,\n')
                for factor, mpi in mbedmpis.items():
                    f.write(f'  .{factor.upper()} = {{ .s=1, .n={len(mpi)}, .p=const_cast<mbedtls_mpi_uint*>(_pl_ds4key_{factor}) }},\n')
                for factor in ('RN', 'RP', 'RQ', 'Vi', 'Vf'):
                    f.write(f'  .{factor} = {{ .s=0, .n=0, .p=nullptr }},\n')
                f.write('};\n')
                f.write('\n')

                f.write('/* DS4ID as parts */\n')
                for page_name, data in ds4id_str.items():
                    f.write(emit_c_array(data, f'__ds4_{page_name}', 'unsigned char', chunk_size=16))
                    f.write('\n')

                f.write('#define HAVE_DS4_KEY 1\n')

anybase = functools.partial(int, base=0)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('file_contains_ds4key', help='Path to a file that contains the DS4Key.')
    p.add_argument('-o', '--output-prefix', help='Prefix of output file.')
    p.add_argument('-p', '--e-padding-size', type=anybase, default=0xfc, help='Padding size for exponent assuming 32-bit usable exponent (default: 0xfc).')
    p.add_argument('--gen-passinglink-ds4key', action='store_true', help='Generate PassingLink DS4Key header (experimental).')
    return p, p.parse_args()

if __name__ == '__main__':
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
            parse_and_extract_key(fw, key_rel_offset, args.e_padding_size, output_prefix_offset, args.gen_passinglink_ds4key)
        except Exception as e:
            print(f'Unable to extract identity block @ 0x{key_abs_offset:x}: {str(e)}')
            traceback.print_exc()
        key_abs_offset += ds4key_len
        fw = fw[key_rel_offset+ds4key_len:]
