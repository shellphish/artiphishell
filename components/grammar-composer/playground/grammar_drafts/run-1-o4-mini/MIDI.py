######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_track_chunk(EVENTS: bytes) -> bytes:
    import sys
    length = len(EVENTS)
    return b'MTrk' + length.to_bytes(4, 'big') + EVENTS

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{HEADER_CHUNK}{TRACK_CHUNK}')
ctx.literal('HEADER_ID', b'MThd')
ctx.literal('HEADER_LEN', b'\x00\x00\x00\x06')
ctx.literal('FORMAT0', b'\x00\x00')
ctx.literal('ONE_TRACK', b'\x00\x01')
ctx.bytes('DIVISION', 2)
ctx.rule('HEADER_CHUNK', b'{HEADER_ID}{HEADER_LEN}{FORMAT0}{ONE_TRACK}{DIVISION}')
ctx.script('TRACK_CHUNK', ['EVENTS'], build_track_chunk)
ctx.rule('EVENTS', b'{NOTE_SEQ}{END_OF_TRACK}')
ctx.rule('NOTE_SEQ', b'{CHANNEL_EVENT}{NOTE_SEQ}')
ctx.literal('NOTE_SEQ', b'')
ctx.regex('DELTA', '[\x00-\x7f]')
ctx.rule('CHANNEL_EVENT', b'{DELTA}{NOTE_ON}')
ctx.rule('CHANNEL_EVENT', b'{DELTA}{NOTE_OFF}')
ctx.regex('NOTE_ON_STATUS', '[\x90-\x9f]')
ctx.regex('DATA7', '[\x00-\x7f]')
ctx.rule('NOTE_ON', b'{NOTE_ON_STATUS}{DATA7}{DATA7}')
ctx.regex('NOTE_OFF_STATUS', '[\x80-\x8f]')
ctx.rule('NOTE_OFF', b'{NOTE_OFF_STATUS}{DATA7}{DATA7}')
ctx.literal('END_OF_TRACK', b'\x00\xff/\x00')
