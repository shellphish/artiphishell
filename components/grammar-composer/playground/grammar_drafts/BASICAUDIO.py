######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_header(ANNOT: bytes, ENCODING_WORD: bytes, SAMPLE_RATE_WORD: bytes, CHANNELS_WORD: bytes) -> bytes:
    """
    Build an *internally* consistent 24-byte header and
    append the annotation.  Offset = 24+len(ANNOT) and
    guaranteed multiple of 8 (because ANNOT_VALID is).
    Data-size is 0xFFFFFFFF (unknown) for simplicity.
    """
    import struct
    offset = 24 + len(ANNOT)
    header = struct.pack('>I', offset)
    header += b'\xff\xff\xff\xff'
    header += ENCODING_WORD
    header += SAMPLE_RATE_WORD
    header += CHANNELS_WORD
    return header + ANNOT

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{AU_FILE}')
ctx.rule('AU_FILE', b'{WELLFORMED_AU}')
ctx.rule('AU_FILE', b'{FUZZY_AU}')
ctx.script('HEADER_VALID', ['ANNOT_VALID', 'ENCODING_WORD', 'SAMPLE_RATE_WORD', 'CHANNELS_WORD'], build_header)
ctx.rule('WELLFORMED_AU', b'.snd{HEADER_VALID}{AUDIO_DATA_VALID}')
ctx.rule('ANNOT_VALID', b'{ANNOT_BLOCK}{ANNOT_VALID}')
ctx.literal('ANNOT_VALID', b'')
ctx.bytes('ANNOT_BLOCK', 8)
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x01')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x02')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x03')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x04')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x05')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x06')
ctx.literal('ENCODING_WORD', b'\x00\x00\x00\x07')
ctx.rule('ENCODING_WORD', b'{DWORD}')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00\x1f@')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00+\x11')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00>\x80')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00V"')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00\xacD')
ctx.literal('SAMPLE_RATE_WORD', b'\x00\x00\xbb\x80')
ctx.rule('SAMPLE_RATE_WORD', b'{DWORD}')
ctx.literal('CHANNELS_WORD', b'\x00\x00\x00\x01')
ctx.literal('CHANNELS_WORD', b'\x00\x00\x00\x02')
ctx.literal('CHANNELS_WORD', b'\x00\x00\x00\x06')
ctx.rule('CHANNELS_WORD', b'{DWORD}')
ctx.rule('AUDIO_DATA_VALID', b'{DATA_CHUNK}{AUDIO_DATA_VALID}')
ctx.literal('AUDIO_DATA_VALID', b'')
ctx.bytes('BLOCK1', 1)
ctx.bytes('BLOCK2', 2)
ctx.bytes('BLOCK4', 4)
ctx.bytes('BLOCK8', 8)
ctx.bytes('BLOCK16', 16)
ctx.bytes('BLOCK32', 32)
ctx.bytes('BLOCK64', 64)
ctx.bytes('BLOCK128', 128)
ctx.bytes('BLOCK256', 256)
ctx.rule('DATA_CHUNK', b'{BLOCK1}')
ctx.rule('DATA_CHUNK', b'{BLOCK2}')
ctx.rule('DATA_CHUNK', b'{BLOCK4}')
ctx.rule('DATA_CHUNK', b'{BLOCK8}')
ctx.rule('DATA_CHUNK', b'{BLOCK16}')
ctx.rule('DATA_CHUNK', b'{BLOCK32}')
ctx.rule('DATA_CHUNK', b'{BLOCK64}')
ctx.rule('DATA_CHUNK', b'{BLOCK128}')
ctx.rule('DATA_CHUNK', b'{BLOCK256}')
ctx.rule('MAGIC_ANY', b'.snd')
ctx.rule('MAGIC_ANY', b'dns.')
ctx.rule('MAGIC_ANY', b'{RANDOM4}')
ctx.bytes('RANDOM4', 4)
ctx.rule('FUZZ_HEADER', b'{DWORD}{DWORD}{DWORD}{DWORD}{DWORD}')
ctx.rule('FUZZ_ANNO', b'{ANNO_CHUNK}{FUZZ_ANNO}')
ctx.literal('FUZZ_ANNO', b'')
ctx.bytes('ANNO_CHUNK', 5)
ctx.rule('FUZZ_DATA', b'{DATA_CHUNK}{FUZZ_DATA}')
ctx.literal('FUZZ_DATA', b'')
ctx.rule('FUZZY_AU', b'{MAGIC_ANY}{FUZZ_HEADER}{FUZZ_ANNO}{FUZZ_DATA}')
ctx.bytes('DWORD', 4)
