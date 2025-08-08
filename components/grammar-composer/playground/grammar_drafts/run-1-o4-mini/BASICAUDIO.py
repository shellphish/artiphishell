######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_au_file(DATA: bytes, ENCODING: bytes, SAMPLE_RATE: bytes, CHANNELS: bytes, ANNOTATION: bytes) -> bytes:
    import struct
    offset = 24 + len(ANNOTATION)
    header = b'.snd' + struct.pack('>I', offset) + struct.pack('>I', len(DATA)) + ENCODING + SAMPLE_RATE + CHANNELS
    return header + ANNOTATION + DATA

######################################################################
# Grammar Rules
######################################################################

ctx.script('START', ['DATA', 'ENCODING', 'SAMPLE_RATE', 'CHANNELS', 'ANNOTATION'], build_au_file)
ctx.literal('DATA', b'')
ctx.bytes('BYTE', 1)
ctx.rule('DATA', b'{BYTE}{DATA}')
ctx.bytes('ENCODING', 4)
ctx.bytes('SAMPLE_RATE', 4)
ctx.bytes('CHANNELS', 4)
ctx.literal('ANNOTATION', b'')
ctx.regex('ASCII_CHAR', '[\\x20-\\x7E]')
ctx.rule('ANNOTATION', b'{ASCII_CHAR}{ANNOTATION}')
