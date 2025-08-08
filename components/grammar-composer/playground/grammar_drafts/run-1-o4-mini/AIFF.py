######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_chunk(CHUNK_ID: bytes, CHUNK_PAYLOAD: bytes) -> bytes:
    import struct
    size = struct.pack('>I', len(CHUNK_PAYLOAD))
    return CHUNK_ID + size + CHUNK_PAYLOAD

def build_form(CHUNKS: bytes) -> bytes:
    import struct
    content = b'AIFF' + CHUNKS
    size = struct.pack('>I', len(content))
    return b'FORM' + size + content

######################################################################
# Grammar Rules
######################################################################

ctx.script('START', ['CHUNKS'], build_form)
ctx.rule('CHUNKS', b'{COMM_CHUNK}{CHUNK_LIST}')
ctx.literal('CHUNK_LIST', b'')
ctx.rule('CHUNK_LIST', b'{CHUNK}{CHUNK_LIST}')
ctx.rule('CHUNK', b'{SSND_CHUNK}')
ctx.rule('CHUNK', b'{MARK_CHUNK}')
ctx.rule('CHUNK', b'{INST_CHUNK}')
ctx.rule('CHUNK', b'{NAME_CHUNK}')
ctx.rule('CHUNK', b'{AUTH_CHUNK}')
ctx.rule('CHUNK', b'{ANNO_CHUNK}')
ctx.rule('CHUNK', b'{UNKNOWN_CHUNK}')
ctx.literal('COMM_ID', b'COMM')
ctx.bytes('COMM_numChannels', 2)
ctx.bytes('COMM_numSampleFrames', 4)
ctx.bytes('COMM_sampleSize', 2)
ctx.bytes('COMM_sampleRate', 10)
ctx.rule('COMM_BODY', b'{COMM_numChannels}{COMM_numSampleFrames}{COMM_sampleSize}{COMM_sampleRate}')
ctx.script('COMM_CHUNK', ['COMM_ID', 'COMM_BODY'], build_chunk)
ctx.literal('SSND_ID', b'SSND')
ctx.bytes('SSND_offset', 4)
ctx.bytes('SSND_blockSize', 4)
ctx.literal('SSND_sampleData_empty', b'')
ctx.bytes('SSND_sampleData_rand', 16)
ctx.rule('SSND_sampleData', b'{SSND_sampleData_empty}')
ctx.rule('SSND_sampleData', b'{SSND_sampleData_rand}')
ctx.rule('SSND_BODY', b'{SSND_offset}{SSND_blockSize}{SSND_sampleData}')
ctx.script('SSND_CHUNK', ['SSND_ID', 'SSND_BODY'], build_chunk)
ctx.literal('MARK_ID', b'MARK')
ctx.literal('MARK_count_0', b'\x00\x00')
ctx.literal('MARK_count_1', b'\x00\x01')
ctx.bytes('MARK_id', 2)
ctx.bytes('MARK_pos', 4)
ctx.regex('MARK_name', '[ -~]{1,8}')
ctx.rule('MARK_marker', b'{MARK_id}{MARK_pos}{MARK_name}')
ctx.rule('MARK_BODY', b'{MARK_count_0}')
ctx.rule('MARK_BODY', b'{MARK_count_1}{MARK_marker}')
ctx.script('MARK_CHUNK', ['MARK_ID', 'MARK_BODY'], build_chunk)
ctx.literal('INST_ID', b'INST')
ctx.bytes('INST_BODY', 8)
ctx.script('INST_CHUNK', ['INST_ID', 'INST_BODY'], build_chunk)
ctx.literal('NAME_ID', b'NAME')
ctx.regex('NAME_text', '[ -~]{1,16}')
ctx.script('NAME_CHUNK', ['NAME_ID', 'NAME_text'], build_chunk)
ctx.literal('AUTH_ID', b'AUTH')
ctx.regex('AUTH_text', '[ -~]{1,16}')
ctx.script('AUTH_CHUNK', ['AUTH_ID', 'AUTH_text'], build_chunk)
ctx.literal('ANNO_ID', b'ANNO')
ctx.regex('ANNO_text', '[ -~]{1,32}')
ctx.script('ANNO_CHUNK', ['ANNO_ID', 'ANNO_text'], build_chunk)
ctx.regex('UNKNOWN_ID', '[A-Z]{4}')
ctx.bytes('UNKNOWN_BODY', 4)
ctx.script('UNKNOWN_CHUNK', ['UNKNOWN_ID', 'UNKNOWN_BODY'], build_chunk)
