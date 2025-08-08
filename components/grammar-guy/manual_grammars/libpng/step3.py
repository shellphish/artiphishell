# PNG File Format Grammar

# PNG Signature rule
# Functions: png_sig_cmp
# The PNG signature is a fixed 8-byte sequence that identifies PNG files
ctx.rule("START", b"\x89PNG\r\n\x1a\n{CHUNKS}")

# Chunks sequence
# Functions: png_read_info, png_read_row
# PNG files consist of multiple chunks, starting with IHDR, followed by IDAT chunks, and ending with IEND
ctx.rule("CHUNKS", b"{IHDR}{IDAT_CHUNKS}{IEND}")

# Multiple IDAT chunks are allowed
ctx.rule("IDAT_CHUNKS", b"{IDAT}{IDAT_CHUNKS}")
ctx.rule("IDAT_CHUNKS", b"{IDAT}")

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
    return create_ihdr(32, 32, data)  # Using smaller dimensions

ctx.script("IHDR", ["IHDR_DATA"], create_ihdr_chunk)
# Format: bit_depth (8) | color_type (6 = RGBA) | compression (0) | filter (0) | interlace (0)
ctx.rule("IHDR_DATA", b"\x08\x06\x00\x00\x00")  # 8-bit RGBA, no interlacing

# IDAT chunk (Image Data)
# Functions: png_read_row -> png_read_IDAT_data -> png_inflate
# Contains the compressed image data that will be processed by png_inflate
def create_idat_chunk(data):
    def create_idat(content):
        import struct
        import zlib
        # Use lower compression level for simpler compressed data
        compressed = zlib.compress(content, 1)
        length = struct.pack(">I", len(compressed))
        chunk = length + b"IDAT" + compressed
        crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
        return chunk + crc
    return create_idat(data)

ctx.script("IDAT", ["IDAT_CONTENT"], create_idat_chunk)

# Raw image data format: each row starts with a filter type byte (0-4)
# followed by RGBA pixels
ctx.rule("IDAT_CONTENT", b"{SCANLINES}")
ctx.rule("SCANLINES", b"{SCANLINE}{SCANLINES}")
ctx.rule("SCANLINES", b"{SCANLINE}")

# Filter types: 0 (None), 1 (Sub), 2 (Up), 3 (Average), 4 (Paeth)
ctx.rule("SCANLINE", b"\x00{ROW_DATA}")  # Using filter type 0 (None)
ctx.rule("SCANLINE", b"\x01{ROW_DATA}")  # Using filter type 1 (Sub)
ctx.rule("SCANLINE", b"\x02{ROW_DATA}")  # Using filter type 2 (Up)
ctx.rule("SCANLINE", b"\x03{ROW_DATA}")  # Using filter type 3 (Average)
ctx.rule("SCANLINE", b"\x04{ROW_DATA}")  # Using filter type 4 (Paeth)

# Row data consists of RGBA pixels
ctx.rule("ROW_DATA", b"{PIXEL}{ROW_DATA}")
ctx.rule("ROW_DATA", b"{PIXEL}")

# RGBA pixels with various colors and alpha values
ctx.rule("PIXEL", b"\xff\x00\x00\xff")  # Red
ctx.rule("PIXEL", b"\x00\xff\x00\xff")  # Green
ctx.rule("PIXEL", b"\x00\x00\xff\xff")  # Blue
ctx.rule("PIXEL", b"\xff\xff\xff\xff")  # White
ctx.rule("PIXEL", b"\x00\x00\x00\xff")  # Black
ctx.rule("PIXEL", b"\xff\xff\x00\x80")  # Yellow with 50% alpha

# IEND chunk (Image End)
# Functions: png_read_end
# Marks the end of the PNG file with an empty chunk
ctx.rule("IEND", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")