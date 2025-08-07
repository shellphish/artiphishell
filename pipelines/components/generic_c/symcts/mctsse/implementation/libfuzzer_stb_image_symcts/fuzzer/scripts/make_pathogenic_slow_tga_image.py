import struct

def p8(val):
    return struct.pack("B", val)

def p16(val):
    return struct.pack("<H", val)

def p32(val):
    return struct.pack("<I", val)

def p64(val):
    return struct.pack("<Q", val)

res = b''
res += p8(0x00)  # offset (ignored)
res += p8(0)     # color type = normal (no color map) (indexed)
res += p8(8 + 2) # image type = 10, (8 == RLE, 3 == grey, 2 == RGB), 10 = RLE + RGB
res += p16(0)    # palette start
res += p16(0)    # palette length
res += p8(0)     # palette bits
res += p16(0)    # x origin
res += p16(0)    # y origin
res += p16(0x131)     # width (largetst allowed value for x with max y)
res += p16(0xffff)    # height
res += p8(32)    # bits per pixel
res += p8(0)     # inverted

for i in range(100):
    res += p8(0x80 | 0x7f) # 0x80 = RLE, 0x7f = 128 times repeated

with open("corpus_pathogenic_slow_tga/pathogenic_slow.tga", "wb") as f:
    f.write(res)

with open("corpus_pathogenic_slow_tga/pathogenic_not_slow.tga", "wb") as f:
    res = list(res)
    res[-100-4] = 0x01
    res[-100-3] = 0x00
    res = bytes(res)
    f.write(res)
