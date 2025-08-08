# Rule: Generate a complete PNG file
# Functions: Entire PNG processing chain
# This is the main rule that generates a valid PNG file
ctx.rule("START", b"{PNG_SIGNATURE}{IHDR_CHUNK}{IDAT_CHUNKS}{IEND_CHUNK}")

# Rule: PNG signature (always constant)
# Functions: png_sig_cmp
# The PNG file signature is always the same 8 bytes
ctx.rule("PNG_SIGNATURE", b"\x89PNG\r\n\x1a\n")

# Rule: IHDR chunk (13 bytes + chunk header/footer)
# Functions: png_handle_IHDR
# Format: Length (4) + "IHDR" + width(4) + height(4) + bit_depth(1) + color_type(1) + compression(1) + filter(1) + interlace(1) + CRC(4)
ctx.rule("IHDR_CHUNK", b"{IHDR_LEN}IHDR{IHDR_DATA}{IHDR_CRC}")
ctx.rule("IHDR_LEN", b"\x00\x00\x00\x0d")  # IHDR data is always 13 bytes
ctx.rule("IHDR_DATA", b"{WIDTH}{HEIGHT}{BIT_DEPTH}{COLOR_TYPE}{COMPRESSION}{FILTER}{INTERLACE}")

# IHDR fields with multiple valid values
ctx.rule("WIDTH", b"\x00\x00\x00\x01")  # 1 pixel width
ctx.rule("WIDTH", b"\x00\x00\x00\x02")  # 2 pixels width
ctx.rule("WIDTH", b"\x00\x00\x00\x04")  # 4 pixels width

ctx.rule("HEIGHT", b"\x00\x00\x00\x01")  # 1 pixel height
ctx.rule("HEIGHT", b"\x00\x00\x00\x02")  # 2 pixels height
ctx.rule("HEIGHT", b"\x00\x00\x00\x04")  # 4 pixels height

ctx.rule("BIT_DEPTH", b"\x08")  # 8 bits
ctx.rule("BIT_DEPTH", b"\x10")  # 16 bits

ctx.rule("COLOR_TYPE", b"\x00")  # Grayscale
ctx.rule("COLOR_TYPE", b"\x02")  # RGB
ctx.rule("COLOR_TYPE", b"\x03")  # Palette
ctx.rule("COLOR_TYPE", b"\x04")  # Grayscale+Alpha
ctx.rule("COLOR_TYPE", b"\x06")  # RGBA

ctx.rule("COMPRESSION", b"\x00")  # zlib compression (only valid value)
ctx.rule("FILTER", b"\x00")      # Basic filtering
ctx.rule("INTERLACE", b"\x00")   # No interlacing
ctx.rule("INTERLACE", b"\x01")   # Adam7 interlacing

ctx.rule("IHDR_CRC", b"\x90\x77\x53\xde")  # CRC for common IHDR values

# Rule: Multiple IDAT chunks
# Functions: png_read_IDAT_data -> png_inflate
ctx.rule("IDAT_CHUNKS", b"{IDAT_CHUNK}")
ctx.rule("IDAT_CHUNKS", b"{IDAT_CHUNK}{IDAT_CHUNKS}")

# Rule: IDAT chunk with zlib compressed data
# Functions: png_read_IDAT_data -> png_inflate
def idat_chunk(data):
    import struct
    import zlib
    return struct.pack(">I4s", len(data), b"IDAT") + data + struct.pack(">I", zlib.crc32(b"IDAT" + data))
ctx.script("IDAT_CHUNK", ["IDAT_DATA"], idat_chunk)
# ctx.rule("IDAT_CHUNK", b"{IDAT_LEN}IDAT{IDAT_DATA}{IDAT_CRC}")
ctx.rule("IDAT_LEN", b"\x00\x00\x00\x0e")  # Length of compressed data
ctx.rule("IDAT_DATA", b"\x78\x9c\x63\x64\x60\x60\x60\x00\x00\x00\x0e\x00\x0d")  # zlib header + minimal compressed data
ctx.rule("IDAT_DATA", b"\x78\x01\x01\x02\x00\xfd\xff\x03\x04\x05\x06\x07\x08")  # Alternative compressed data
ctx.rule("IDAT_CRC", b"\xd3\x89\x42\xda")  # CRC for first IDAT data
ctx.rule("IDAT_CRC", b"\x1d\x29\x34\xfa")  # CRC for second IDAT data

# Rule: IEND chunk (empty, just marks end of file)
# Functions: png_handle_IEND
# Always the same bytes
ctx.rule("IEND_CHUNK", b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")