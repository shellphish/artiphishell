######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def encode_vlq(NUM: bytes) -> bytes:
    num = int.from_bytes(NUM, byteorder='big')
    vlq = bytearray()
    while True:
        b = num & 127
        num >>= 7
        if num > 0:
            b |= 128
        vlq.insert(0, b)
        if num == 0:
            break
    return bytes(vlq)

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'MThd{HEADER_CHUNK}{TRACK_CHUNKS}')
ctx.rule('HEADER_CHUNK', b'{HEADER_LENGTH}{HEADER_DATA}')
ctx.literal('HEADER_LENGTH', b'\x00\x00\x00\x06')
ctx.rule('HEADER_DATA', b'{FORMAT}{NTRKS}{DIVISION}')
ctx.literal('FORMAT', b'\x00\x00')
ctx.literal('FORMAT', b'\x00\x01')
ctx.literal('FORMAT', b'\x00\x02')
ctx.literal('NTRKS', b'\x00\x01')
ctx.literal('NTRKS', b'\x00\x02')
ctx.literal('NTRKS', b'\x00\x04')
ctx.literal('DIVISION', b'\x00`')
ctx.literal('DIVISION', b'\x00x')
ctx.literal('DIVISION', b'\x01\x00')
ctx.rule('TRACK_CHUNKS', b'{TRACK_CHUNK}{TRACK_CHUNKS}')
ctx.literal('TRACK_CHUNKS', b'')
ctx.rule('TRACK_CHUNK', b'MTrk{TRACK_LENGTH}{TRACK_DATA}')
ctx.literal('TRACK_LENGTH', b'\x00\x00\x00\x04')
ctx.literal('TRACK_LENGTH', b'\x00\x00\x00\x08')
ctx.literal('TRACK_LENGTH', b'\x00\x00\x01\x00')
ctx.rule('TRACK_DATA', b'{EVENT}{TRACK_DATA}')
ctx.rule('TRACK_DATA', b'{END_OF_TRACK}')
ctx.rule('EVENT', b'{DELTA_TIME}{EVENT_TYPE}')
ctx.literal('DELTA_TIME', b'\x00')
ctx.literal('DELTA_TIME', b'@')
ctx.literal('DELTA_TIME', b'\x7f')
ctx.literal('DELTA_TIME', b'\x81\x00')
ctx.literal('DELTA_TIME', b'\xff\x7f')
ctx.rule('EVENT_TYPE', b'{MIDI_EVENT}')
ctx.rule('EVENT_TYPE', b'{META_EVENT}')
ctx.rule('EVENT_TYPE', b'{SYSEX_EVENT}')
ctx.literal('MIDI_EVENT', b'\x90<@')
ctx.literal('MIDI_EVENT', b'\x80<@')
ctx.literal('MIDI_EVENT', b'\xb0\x07d')
ctx.literal('MIDI_EVENT', b'\xc0\x00')
ctx.literal('META_EVENT', b'\xff\x01\x03ABC')
ctx.literal('META_EVENT', b'\xffQ\x03\x07\xa1 ')
ctx.literal('META_EVENT', b'\xffX\x04\x04\x02\x18\x08')
ctx.literal('END_OF_TRACK', b'\x00\xff/\x00')
ctx.literal('SYSEX_EVENT', b'\xf0\x04~\x00\t\xf7')
