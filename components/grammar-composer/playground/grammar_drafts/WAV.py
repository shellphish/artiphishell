######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_data_chunk(AUDIO_DATA: bytes) -> bytes:
    import struct
    return b'data' + struct.pack('<I', len(AUDIO_DATA)) + AUDIO_DATA

def build_fmt_chunk(FMT_BODY: bytes) -> bytes:
    import struct
    return b'fmt ' + struct.pack('<I', len(FMT_BODY)) + FMT_BODY

def build_generic_chunk(CHUNK_ID: bytes, CHUNK_CONTENT: bytes) -> bytes:
    import struct
    return CHUNK_ID + struct.pack('<I', len(CHUNK_CONTENT)) + CHUNK_CONTENT

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{RIFF_ID}{U32}{WAVE_ID}{CHUNK_LIST}')
ctx.literal('WAVE_ID', b'WAVE')
ctx.literal('RIFF_ID', b'RIFF')
ctx.literal('RIFX_ID', b'RIFX')
ctx.rule('RIFF_ID', b'RIFF')
ctx.rule('RIFF_ID', b'RIFX')
ctx.rule('CHUNK_LIST', b'{CHUNK}{CHUNK_LIST}')
ctx.literal('CHUNK_LIST', b'')
ctx.rule('CHUNK', b'{FMT_CHUNK_VALID}')
ctx.rule('CHUNK', b'{FMT_CHUNK_INVALID}')
ctx.rule('CHUNK', b'{DATA_CHUNK_VALID}')
ctx.rule('CHUNK', b'{DATA_CHUNK_INVALID}')
ctx.rule('CHUNK', b'{LIST_CHUNK}')
ctx.rule('CHUNK', b'{FACT_CHUNK}')
ctx.rule('CHUNK', b'{CUE_CHUNK}')
ctx.rule('CHUNK', b'{SMPL_CHUNK}')
ctx.rule('CHUNK', b'{GENERIC_CHUNK}')
ctx.script('FMT_CHUNK_VALID', ['FMT_BODY'], build_fmt_chunk)
ctx.rule('FMT_CHUNK_INVALID', b'fmt {FOUR_BYTES}{FMT_BODY}{PAD_BYTE_OPT}')
ctx.rule('FMT_BODY_PCM', b'{AudioFormat_PCM}{NumChannels}{SampleRate}{ByteRate}{BlockAlign}{BitsPerSample}')
ctx.rule('FMT_BODY_EXT', b'{AudioFormat_EXT}{NumChannels}{SampleRate}{ByteRate}{BlockAlign}{BitsPerSample}\x16\x00{BYTES_22}')
ctx.rule('FMT_BODY', b'{FMT_BODY_PCM}')
ctx.rule('FMT_BODY', b'{FMT_BODY_EXT}')
ctx.script('DATA_CHUNK_VALID', ['AUDIO_DATA'], build_data_chunk)
ctx.rule('DATA_CHUNK_INVALID', b'data{FOUR_BYTES}{AUDIO_DATA}{PAD_BYTE_OPT}')
ctx.rule('LIST_CHUNK', b'LIST{U32}INFO{CHUNK_CONTENT}')
ctx.rule('FACT_CHUNK', b'fact{U32}{CHUNK_CONTENT}')
ctx.rule('CUE_CHUNK', b'cue {U32}{CHUNK_CONTENT}')
ctx.rule('SMPL_CHUNK', b'smpl{U32}{CHUNK_CONTENT}')
ctx.script('GENERIC_CHUNK', ['CHUNK_ID', 'CHUNK_CONTENT'], build_generic_chunk)
ctx.literal('AudioFormat_PCM', b'\x01\x00')
ctx.literal('AudioFormat_IEEE', b'\x03\x00')
ctx.literal('AudioFormat_EXT', b'\xfe\xff')
ctx.rule('AudioFormat', b'{AudioFormat_PCM}')
ctx.rule('AudioFormat', b'{AudioFormat_IEEE}')
ctx.rule('AudioFormat', b'{AudioFormat_EXT}')
ctx.literal('AudioFormat_PCM', b'\x01\x00')
ctx.literal('AudioFormat_EXT', b'\xfe\xff')
ctx.literal('MONO', b'\x01\x00')
ctx.literal('STEREO', b'\x02\x00')
ctx.rule('NumChannels', b'{MONO}')
ctx.rule('NumChannels', b'{STEREO}')
ctx.rule('NumChannels', b'{U16}')
ctx.literal('SR_44100', b'D\xac\x00\x00')
ctx.literal('SR_48000', b'\x80\xbb\x00\x00')
ctx.rule('SampleRate', b'{SR_44100}')
ctx.rule('SampleRate', b'{SR_48000}')
ctx.rule('SampleRate', b'{U32}')
ctx.rule('ByteRate', b'{U32}')
ctx.rule('BlockAlign', b'{U16}')
ctx.literal('BPS_8', b'\x08\x00')
ctx.literal('BPS_16', b'\x10\x00')
ctx.literal('BPS_24', b'\x18\x00')
ctx.literal('BPS_32', b' \x00')
ctx.rule('BitsPerSample', b'{BPS_8}')
ctx.rule('BitsPerSample', b'{BPS_16}')
ctx.rule('BitsPerSample', b'{BPS_24}')
ctx.rule('BitsPerSample', b'{BPS_32}')
ctx.rule('BitsPerSample', b'{U16}')
ctx.bytes('BYTES_16', 16)
ctx.bytes('BYTES_32', 32)
ctx.bytes('BYTES_64', 64)
ctx.bytes('BYTES_256', 256)
ctx.bytes('BYTES_1024', 1024)
ctx.bytes('BYTES_4096', 4096)
ctx.rule('AUDIO_DATA', b'{BYTES_16}')
ctx.rule('AUDIO_DATA', b'{BYTES_32}')
ctx.rule('AUDIO_DATA', b'{BYTES_64}')
ctx.rule('AUDIO_DATA', b'{BYTES_256}')
ctx.rule('AUDIO_DATA', b'{BYTES_1024}')
ctx.rule('AUDIO_DATA', b'{BYTES_4096}')
ctx.rule('CHUNK_CONTENT', b'{BYTES_16}')
ctx.rule('CHUNK_CONTENT', b'{BYTES_64}')
ctx.rule('CHUNK_CONTENT', b'{BYTES_256}')
ctx.bytes('PAD_ONE', 1)
ctx.rule('PAD_BYTE_OPT', b'{PAD_ONE}')
ctx.literal('PAD_BYTE_OPT', b'')
ctx.bytes('U8', 1)
ctx.bytes('U16', 2)
ctx.bytes('U32', 4)
ctx.regex('CHUNK_ID', '[A-Z0-9 ]{4}')
ctx.bytes('BYTES_22', 22)
ctx.bytes('FOUR_BYTES', 4)
