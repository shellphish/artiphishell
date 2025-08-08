# Rule: START - Generates a complete PNG file
# Functions: LLVMFuzzerTestOneInput
# This is the entry point that generates a complete PNG file with required chunks
ctx.rule("START", b"{PNG_SIGNATURE}{IHDR_CHUNK}{IDAT_CHUNK}{IEND_CHUNK}")

# Rule: PNG_SIGNATURE - The standard PNG file signature
# Functions: png_sig_cmp
# The PNG signature is a fixed 8-byte sequence that identifies PNG files
ctx.rule("PNG_SIGNATURE", b"\x89PNG\r\n\x1a\n")

# Rule: IHDR_CHUNK - Generates the IHDR chunk with image metadata
# Functions: png_handle_IHDR
# Contains length (4 bytes), chunk type "IHDR", chunk data (13 bytes), and CRC (4 bytes)
def create_ihdr_chunk(width, height, bit_depth, color_type, compression, filter, interlace):
    import struct
    import zlib
    # Convert binary values to integers
    width = int.from_bytes(width, 'big')
    height = int.from_bytes(height, 'big')
    bit_depth = int.from_bytes(bit_depth, 'big')
    color_type = int.from_bytes(color_type, 'big')
    compression = int.from_bytes(compression, 'big')
    filter = int.from_bytes(filter, 'big')
    interlace = int.from_bytes(interlace, 'big')
    # IHDR is always 13 bytes
    data = b"IHDR" + struct.pack(">IIBBBBB", width, height, bit_depth, color_type, compression, filter, interlace)
    crc = zlib.crc32(data)
    return struct.pack(">I", 13) + data + struct.pack(">I", crc)
ctx.script("IHDR_CHUNK", ["WIDTH", "HEIGHT", "BIT_DEPTH", "COLOR_TYPE", "COMPRESSION", "FILTER", "INTERLACE"], create_ihdr_chunk)

# Rule: IDAT_CHUNK - Generates the IDAT chunk with compressed image data
# Functions: png_read_IDAT_data, png_zlib_inflate, png_inflate
# Contains length (4 bytes), chunk type "IDAT", zlib-compressed data, and CRC (4 bytes)
def create_idat_chunk(data):
    import struct
    import zlib
    # Compress the data with zlib
    compressed = zlib.compress(data)
    chunk_data = b"IDAT" + compressed
    crc = zlib.crc32(chunk_data)
    return struct.pack(">I", len(compressed)) + chunk_data + struct.pack(">I", crc)
ctx.script("IDAT_CHUNK", ["PIXEL_DATA"], create_idat_chunk)

# Rule: IEND_CHUNK - Generates the IEND chunk that marks the end of the PNG
# Functions: png_handle_IEND
# Contains length (4 bytes), chunk type "IEND", no data, and CRC (4 bytes)
def create_iend_chunk():
    import struct
    import zlib
    data = b"IEND"
    crc = zlib.crc32(data)
    return struct.pack(">I", 0) + data + struct.pack(">I", crc)
ctx.rule("IEND_CHUNK", create_iend_chunk())

# Image dimension rules - Keep dimensions reasonable to avoid timeouts
ctx.rule("WIDTH", b"\x00\x00\x00\x80")  # 128 pixels
ctx.rule("HEIGHT", b"\x00\x00\x00\x80")  # 128 pixels

# Image format rules
ctx.rule("BIT_DEPTH", b"\x08")  # 8 bits per channel
ctx.rule("COLOR_TYPE", b"\x02")  # RGB format
ctx.rule("COMPRESSION", b"\x00")  # zlib compression
ctx.rule("FILTER", b"\x00")  # No filtering
ctx.rule("INTERLACE", b"\x00")  # No interlacing

# Rule: PIXEL_DATA - Generates raw pixel data to be compressed
# Functions: png_read_row
# Generates RGB pixel data (3 bytes per pixel)
ctx.rule("PIXEL_DATA", b"{RGB_PIXEL}{PIXEL_DATA}")
ctx.rule("PIXEL_DATA", b"{RGB_PIXEL}")
ctx.rule("RGB_PIXEL", b"{BYTE}{BYTE}{BYTE}")
ctx.regex("BYTE", "[\x00-\xff]")