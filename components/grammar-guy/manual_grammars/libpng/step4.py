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
    return create_ihdr(8, 8, data)  # Using small dimensions

ctx.script("IHDR", ["IHDR_DATA"], create_ihdr_chunk)

# IHDR data with various valid combinations
ctx.rule("IHDR_DATA", b"\x08\x06\x00\x00\x00")  # 8-bit RGBA
ctx.rule("IHDR_DATA", b"\x08\x02\x00\x00\x00")  # 8-bit RGB
ctx.rule("IHDR_DATA", b"\x08\x04\x00\x00\x00")  # 8-bit grayscale+alpha
ctx.rule("IHDR_DATA", b"\x08\x00\x00\x00\x00")  # 8-bit grayscale

# IDAT chunk (Image Data)
# Functions: png_read_row -> png_read_IDAT_data -> png_inflate
# Contains the compressed image data that will be processed by png_inflate
def create_idat_chunk(data):
    import struct
    import zlib
    # Create a zlib stream with minimal compression
    # CMF byte: 8 = deflate compression with 32k window
    # FLG byte: 0 = no preset dictionary, fastest compression
    zlib_header = b"\x78\x01"
    # Compress the actual data
    compressor = zlib.compressobj(level=0, wbits=15)  # Standard zlib compression
    compressed = compressor.compress(data) + compressor.flush()
    # Create the IDAT chunk
    final_data = compressed  # zlib.compress already includes header and checksum
    length = struct.pack(">I", len(final_data))
    chunk = length + b"IDAT" + final_data
    crc = struct.pack(">I", zlib.crc32(b"IDAT" + final_data) & 0xFFFFFFFF)
    return chunk + crc

ctx.script("IDAT", ["IDAT_CONTENT"], create_idat_chunk)

# Raw image data format: each row starts with a filter type byte
# followed by pixel data
ctx.rule("IDAT_CONTENT", b"{SCANLINES}")
ctx.rule("SCANLINES", b"{SCANLINE}{SCANLINES}")
ctx.rule("SCANLINES", b"{SCANLINE}")

# Filter types: 0 (None), 1 (Sub), 2 (Up), 3 (Average), 4 (Paeth)
ctx.rule("SCANLINE", b"{FILTER_TYPE}{ROW_DATA}")

ctx.rule("FILTER_TYPE", b"\x00")  # None
ctx.rule("FILTER_TYPE", b"\x01")  # Sub
ctx.rule("FILTER_TYPE", b"\x02")  # Up
ctx.rule("FILTER_TYPE", b"\x03")  # Average
ctx.rule("FILTER_TYPE", b"\x04")  # Paeth

# Row data consists of pixels
ctx.rule("ROW_DATA", b"{PIXEL}{ROW_DATA}")
ctx.rule("ROW_DATA", b"{PIXEL}")

# RGBA pixels with various colors and alpha values
ctx.rule("PIXEL", b"\xff\x00\x00\xff")  # Red
ctx.rule("PIXEL", b"\x00\xff\x00\xff")  # Green
ctx.rule("PIXEL", b"\x00\x00\xff\xff")  # Blue
ctx.rule("PIXEL", b"\xff\xff\xff\xff")  # White
ctx.rule("PIXEL", b"\x00\x00\x00\xff")  # Black
ctx.rule("PIXEL", b"\xff\xff\x00\x80")  # Yellow with 50% alpha
ctx.rule("PIXEL", b"{RANDOM_PIXEL}")  # Random pixel data

# Random pixel data to increase coverage
ctx.rule("RANDOM_PIXEL", b"{BYTE}{BYTE}{BYTE}{BYTE}")
ctx.regex("BYTE", "[\x00-\xff]")

# IEND chunk (Image End)
# Functions: png_read_end
# Marks the end of the PNG file with an empty chunk
ctx.rule("IEND", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")