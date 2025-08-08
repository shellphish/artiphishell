# Rule: START
# Functions: LLVMFuzzerTestOneInput
# Semantics: Top-level rule that generates a complete PNG file
ctx.rule("START", b"{PNG_SIGNATURE}{IHDR_CHUNK}{OPTIONAL_CHUNKS}{IDAT_CHUNK}{IEND_CHUNK}")

# Rule: PNG_SIGNATURE
# Functions: png_sig_cmp
# Semantics: The standard PNG signature
ctx.rule("PNG_SIGNATURE", b"\x89PNG\r\n\x1a\n")

# Rule: IHDR_CHUNK
# Functions: png_get_IHDR
# Semantics: Image header chunk with required metadata
def create_ihdr(width, height):
    import struct
    import zlib
    
    # Create IHDR data
    bit_depth = 8  # Using 8 bit depth as required by target function
    color_type = 2  # PNG_COLOR_TYPE_RGB
    compression = 0  # Standard compression
    filter_type = 64  # PNG_INTRAPIXEL_DIFFERENCING
    interlace = 0  # No interlacing
    
    data = struct.pack(">II", int(width), int(height)) + bytes([bit_depth, color_type, compression, filter_type, interlace])
    chunk_type = b"IHDR"
    
    # Calculate CRC of chunk type + data
    crc = zlib.crc32(chunk_type + data) & 0xffffffff
    
    # Assemble chunk
    length = struct.pack(">I", len(data))
    return length + chunk_type + data + struct.pack(">I", crc)

ctx.script("IHDR_CHUNK", ["WIDTH", "HEIGHT"], create_ihdr)

# Rule: WIDTH, HEIGHT
# Functions: png_get_IHDR
# Semantics: Valid image dimensions (keeping them small for efficiency)
ctx.rule("WIDTH", "32")  # 32 pixels
ctx.rule("HEIGHT", "32")  # 32 pixels

# Rule: IDAT_CHUNK
# Functions: png_read_row, png_do_read_intrapixel
# Semantics: Image data chunk with intrapixel differencing filter
def create_idat(content):
    import struct
    import zlib
    
    chunk_type = b"IDAT"
    # Use a proper zlib compression level
    compressed_data = zlib.compress(content, level=6)
    length = struct.pack(">I", len(compressed_data))
    crc = zlib.crc32(chunk_type + compressed_data) & 0xffffffff
    
    return length + chunk_type + compressed_data + struct.pack(">I", crc)

ctx.script("IDAT_CHUNK", ["IDAT_CONTENT"], create_idat)

# Rule: IDAT_CONTENT
# Functions: png_do_read_intrapixel
# Semantics: Raw image data with intrapixel differencing filter
def create_idat_content():
    width = 32
    height = 32
    bytes_per_pixel = 3  # RGB
    
    # Create scanlines with filter type 64 (intrapixel differencing)
    content = bytearray()
    for _ in range(height):
        # Add filter type byte
        content.append(64)  # PNG_INTRAPIXEL_DIFFERENCING
        # Add RGB data
        for i in range(width * bytes_per_pixel):
            content.append(i % 256)
    
    return bytes(content)

ctx.script("IDAT_CONTENT", [], create_idat_content)

# Rule: IEND_CHUNK
# Functions: png_read_end
# Semantics: Required end marker for PNG file
ctx.rule("IEND_CHUNK", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")

# Rule: OPTIONAL_CHUNKS
# Functions: Various png chunk handlers
# Semantics: Optional PNG chunks (empty for minimal case)
ctx.rule("OPTIONAL_CHUNKS", b"")