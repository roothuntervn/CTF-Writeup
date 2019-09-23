c = ' 1 1 . 1 . . . . 1 1 . 1 1 . . . 1 1 . . . . 1 . 1 1 . . . 1 1 . 1 1 . 1 . 1 1 . 1 1 1 . . 1 1'
d = c.replace('.','0').replace(' ','')
print(hex(int(d,2))[2:].decode('hex'))