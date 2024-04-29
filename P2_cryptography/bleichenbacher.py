#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py “from_username+to_username+100.00”
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    tmp = hex(0x0001FF003031300D060960864801650304020105000420)
    tmp += hashlib.sha256(message.encode("latin-1")).hexdigest() + hex(0x00)[2:] * 402

    forged_sig, check = integer_nthroot(int(tmp, 16), 3)
    forged_sig = forged_sig if check else forged_sig + 1

    print(bytes_to_base64(integer_to_bytes(forged_sig, 256)))


if __name__ == "__main__":
    main()
