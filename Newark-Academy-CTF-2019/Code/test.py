#!/usr/bin/env python3

from PIL import Image

im = Image.open('../Files/The_phuzzy_photo.png')
im2 = Image.new('RGB', (300, 300))
im2.putdata(list(im.getdata())[::6])
im2.show()