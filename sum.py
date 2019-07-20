#!/usr/bin/env python3
# SPDX-License-Identifier: Unlicense

import sys

with open(sys.argv[1], 'rb') as f:
    checksum = 0
    while True:
        w = f.read(1)
        if len(w) == 0:
            break
        checksum += int.from_bytes(w, 'little', signed=False)
        checksum &= 0xffff
print(hex(checksum))
