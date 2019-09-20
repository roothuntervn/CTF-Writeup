from pwn import *

p = remote('shell.2019.nactf.com', 31425)
p.recvuntil('> ')
p.sendline('r')
num = p.recv().split('\n')[0].strip()
num_1 = long(str(num)[4:12]) ** 2
num_2 = long(str(num_1)[4:12]) ** 2
p.sendline('g')
p.recvuntil('> ')
p.sendline(str(num_1))
p.recv()
p.sendline(str(num_2))
p.interactive()