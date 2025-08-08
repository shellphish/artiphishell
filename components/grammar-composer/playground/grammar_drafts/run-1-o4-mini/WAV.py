######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{RIFF}{RIFF_SIZE0}{WAVE}{FMT_CHUNK}{DATA0}')
ctx.rule('START', b'{RIFF}{RIFF_SIZE4}{WAVE}{FMT_CHUNK}{DATA4}')
ctx.rule('START', b'{RIFF}{RIFF_SIZE8}{WAVE}{FMT_CHUNK}{DATA8}')
ctx.literal('RIFF', b'RIFF')
ctx.literal('WAVE', b'WAVE')
ctx.literal('RIFF_SIZE0', b'$\x00\x00\x00')
ctx.literal('RIFF_SIZE4', b'(\x00\x00\x00')
ctx.literal('RIFF_SIZE8', b',\x00\x00\x00')
ctx.rule('FMT_CHUNK', b'fmt \x10\x00\x00\x00{FMT_BODY}')
ctx.bytes('FMT_BODY', 16)
ctx.literal('DATA0', b'data\x00\x00\x00\x00')
ctx.rule('DATA4', b'data\x04\x00\x00\x00{BYTES4}')
ctx.bytes('BYTES4', 4)
ctx.rule('DATA8', b'data\x08\x00\x00\x00{BYTES8}')
ctx.bytes('BYTES8', 8)
