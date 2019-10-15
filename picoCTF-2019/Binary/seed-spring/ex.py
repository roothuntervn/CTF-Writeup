from pwn import *
import sys
import ctypes

LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

argv = sys.argv

DEBUG = True
# BINARY = './seed_spring'

# context.binary = BINARY
context.terminal = ['tmux', 'splitw', '-v']

def attach_gdb():
  gdb.attach(sh)


if DEBUG:
  context.log_level = 'debug'


def start():
  global sh
  if len(argv) < 2:
    stdout = process.PTY
    stdin = process.PTY

    sh = process(BINARY, stdout=stdout, stdin=stdin)

    # if DEBUG:
    #   attach_gdb()

    REMOTE = False
  else:
    # sh = remote('2019shell1.picoctf.com', 4160)
    sh = remote('localhost', 4160)
    REMOTE = True

for i in range(100):

  start()
  try:
    LIBC.srand(LIBC.time(0)-i)

    for i in range(30):
      sh.sendlineafter(': ', str(LIBC.rand() & 0xf))
      

    sh.interactive()
  except:
    print 'pass'