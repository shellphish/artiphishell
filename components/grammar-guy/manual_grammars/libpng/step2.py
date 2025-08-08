# PNG File Format Grammar

# PNG Signature rule
# Functions: png_sig_cmp
# The PNG signature is a fixed 8-byte sequence that identifies PNG files
ctx.rule("START", b"\x89PNG\r\n\x1a\n{CHUNKS}")

# Chunks sequence
# Functions: png_read_info, png_read_row
# PNG files consist of multiple chunks, starting with IHDR, followed by IDAT chunks, and ending with IEND
ctx.rule("CHUNKS", b"{IHDR}{IDAT}{IEND}")

# IHDR chunk (Image Header)
# Functions: png_get_IHDR
# Contains critical image metadata: width, height, bit depth, color type, etc.
def create_ihdr_chunk(data):
    def create_ihdr(width, height, other_data):
        import struct
        import zlib
        data = struct.pack(">II", width, height) + other_data
        length = struct.pack(">I", 13)  # IHDR data is always 13 bytes
        chunk = length + b"IHDR" + data
        crc = struct.pack(">I", zlib.crc32(b"IHDR" + data) & 0xFFFFFFFF)
        return chunk + crc
    return create_ihdr(100, 100, data)

ctx.script("IHDR", ["IHDR_DATA"], create_ihdr_chunk)
ctx.rule("IHDR_DATA", b"\x08\x06\x00\x00\x00")  # 8-bit RGBA, no interlacing

# IDAT chunk (Image Data)
# Functions: png_read_row -> png_inflate
# Contains the compressed image data that will be processed by png_inflate
def create_idat_chunk(data):
    def create_idat(content):
        import struct
        import zlib
        compressed = zlib.compress(content)
        length = struct.pack(">I", len(compressed))
        chunk = length + b"IDAT" + compressed
        crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
        return chunk + crc
    return create_idat(data)

ctx.script("IDAT", ["IDAT_CONTENT"], create_idat_chunk)
ctx.rule("IDAT_CONTENT", b"{SCANLINE}{IDAT_CONTENT}")
ctx.rule("IDAT_CONTENT", b"{SCANLINE}")

# Scanline format: filter type (0) + RGBA data for 100 pixels
ctx.rule("SCANLINE", b"\x00{PIXEL}{PIXEL}{PIXEL}")
ctx.rule("PIXEL", b"\xff\x00\x00\xff")  # RGBA pixel (red with full alpha)

# IEND chunk (Image End)
# Functions: png_read_end
# Marks the end of the PNG file
ctx.rule("IEND", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")