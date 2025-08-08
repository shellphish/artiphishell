######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def int_to_bytes(NUM: bytes) -> bytes:
    try:
        num = int(NUM.decode())
        return num.to_bytes(4, byteorder='big')
    except:
        return b'\x00\x00\x00\x18'

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{HEADER}{INFO}{AUDIO_DATA}')
ctx.rule('HEADER', b'{MAGIC}{HEADER_SIZE}{DATA_SIZE}{ENCODING}{SAMPLE_RATE}{CHANNELS}')
ctx.literal('MAGIC', b'.snd')
ctx.literal('HEADER_SIZE', b'\x00\x00\x00\x18')
ctx.literal('HEADER_SIZE', b'\x00\x00\x00 ')
ctx.literal('HEADER_SIZE', b'\x00\x00\x00(')
ctx.literal('DATA_SIZE', b'\x00\x00\x04\x00')
ctx.literal('DATA_SIZE', b'\x00\x00\x08\x00')
ctx.literal('DATA_SIZE', b'\x00\x00\x10\x00')
ctx.literal('ENCODING', b'\x00\x00\x00\x01')
ctx.literal('ENCODING', b'\x00\x00\x00\x02')
ctx.literal('ENCODING', b'\x00\x00\x00\x03')
ctx.literal('SAMPLE_RATE', b'\x00\x00\x1f@')
ctx.literal('SAMPLE_RATE', b'\x00\x00+\x11')
ctx.literal('SAMPLE_RATE', b'\x00\x00\xacD')
ctx.literal('CHANNELS', b'\x00\x00\x00\x01')
ctx.literal('CHANNELS', b'\x00\x00\x00\x02')
ctx.literal('INFO', b'')
ctx.literal('INFO', b'Created by Fuzzer')
ctx.rule('AUDIO_DATA', b'{AUDIO_BLOCK}{AUDIO_BLOCK}{AUDIO_BLOCK}{AUDIO_BLOCK}')
ctx.literal('AUDIO_BLOCK', b'\x00' * 256)
ctx.literal('AUDIO_BLOCK', b'\x7f' * 256)
ctx.literal('AUDIO_BLOCK', b'\xff' * 256)
ctx.literal('AUDIO_BLOCK', b'\x00\x7f\xff' * 85 + b'\x00')
ctx.literal('AUDIO_BLOCK', b'U' * 256)
ctx.literal('AUDIO_BLOCK', b'\x00@\x80\xc0' * 64)
ctx.literal('AUDIO_BLOCK', b'\x80@\x00@\x80\xc0\xff\xc0' * 32)
