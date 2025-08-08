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
    # For an 8x8 image, each row is 8 pixels * 4 bytes + 1 filter byte
    # Total size is 33 bytes * 8 rows = 264 bytes
    content = b""
    for i in range(8):
        # Filter type (0-4) followed by 8 RGBA pixels
        filter_type = i % 5  # Use all filter types
        row = bytes([filter_type]) + (b"\xff\x00\x00\xff" * 8)
        content += row

    # Create a proper zlib stream
    # Use compress() with default settings to ensure proper zlib headers and checksum
    # Try different compression levels to increase coverage
    compressed = zlib.compress(content, level=i % 10)
    
    # Create the IDAT chunk
    length = struct.pack(">I", len(compressed))
    chunk = length + b"IDAT" + compressed
    crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    return chunk + crc

ctx.script("IDAT", ["DUMMY"], create_idat_chunk)
ctx.rule("DUMMY", b"")  # Dummy rule since we don't need input for IDAT content

# IEND chunk (Image End)
# Functions: png_read_end
# Marks the end of the PNG file with an empty chunk
ctx.rule("IEND", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")