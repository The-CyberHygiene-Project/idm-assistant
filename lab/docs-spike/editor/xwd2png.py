"""Convert an Xvfb -fbdir XWD framebuffer (24-bit, 32bpp ZPixmap, little endian) to PNG. Usage: python3 -I xwd2png.py IN OUT.png"""
import struct, sys
from PIL import Image
b = open(sys.argv[1], "rb").read()
f = struct.unpack(">25I", b[:100]); hs, w, h, bpl, ncol = f[0], f[4], f[5], f[12], f[19]
off = hs + ncol * 12
raw = b[off:off + bpl * h]
Image.frombuffer("RGB", (w, h), raw, "raw", "BGRX", bpl, 1).save(sys.argv[2])
