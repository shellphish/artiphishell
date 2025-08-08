######################################################################
# Helper Functions
######################################################################

def BUILD_AIFC(FVER_CHUNK: bytes, COMM_CHUNK_AIFC: bytes, SSND_CHUNK: bytes, EXTRA_LIST: bytes) -> bytes:
    body = b'AIFC' + FVER_CHUNK + COMM_CHUNK_AIFC + SSND_CHUNK + EXTRA_LIST
    return b'FORM' + be32(len(body)) + body

def BUILD_AIFF(COMM_CHUNK_AIFF: bytes, SSND_CHUNK: bytes, EXTRA_LIST: bytes) -> bytes:
    body = b'AIFF' + COMM_CHUNK_AIFF + SSND_CHUNK + EXTRA_LIST
    return b'FORM' + be32(len(body)) + body

def MK_COMM_AIFC(CHANNELS: bytes, FRAMECOUNT: bytes, SAMPLEBITS: bytes, SAMPLERATE: bytes, COMPTYPE: bytes, COMPNAME: bytes) -> bytes:
    return _chunk(b'COMM', CHANNELS + FRAMECOUNT + SAMPLEBITS + SAMPLERATE + COMPTYPE + COMPNAME)

def MK_COMM_AIFF(CHANNELS: bytes, FRAMECOUNT: bytes, SAMPLEBITS: bytes, SAMPLERATE: bytes) -> bytes:
    return _chunk(b'COMM', CHANNELS + FRAMECOUNT + SAMPLEBITS + SAMPLERATE)

def MK_FVER(VERSION: bytes) -> bytes:
    return _chunk(b'FVER', VERSION)

def MK_MARK(MARKCOUNT: bytes, MRECS: bytes) -> bytes:
    return _chunk(b'MARK', MARKCOUNT + MRECS)

def MK_MARKER(MID: bytes, MPOS: bytes, MNAME: bytes) -> bytes:
    return MID + MPOS + _pstr(MNAME)

def MK_SIMPLE(CID: bytes, DATA: bytes) -> bytes:
    return _chunk(CID, DATA)

def MK_SSND(OFFSET: bytes, BLOCKSIZE: bytes, AUDPAY: bytes) -> bytes:
    return _chunk(b'SSND', OFFSET + BLOCKSIZE + AUDPAY)

def MK_TEXT(NAME: bytes, TXT_CONTENT: bytes) -> bytes:
    return _chunk(NAME, _pstr(TXT_CONTENT))

def MK_UNKNOWN_BAD(FOURCC: bytes, GEN_DATA: bytes) -> bytes:
    return _chunk_bad(FOURCC, GEN_DATA)

def MK_UNKNOWN_GOOD(FOURCC: bytes, GEN_DATA: bytes) -> bytes:
    return _chunk(FOURCC, GEN_DATA)

def _chunk(cid: bytes, data: bytes) -> bytes:
    body = _pad(data)
    return cid[:4] + be32(len(body)) + body

def _chunk_bad(cid: bytes, data: bytes) -> bytes:
    body = _pad(data)
    return cid[:4] + be32(len(body) + 1) + body

def _pad(b: bytes) -> bytes:
    return b if len(b) & 1 == 0 else b + b'\x00'

def _pstr(buf: bytes) -> bytes:
    s = buf[:255]
    return bytes([len(s)]) + s

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def be32(n: int) -> bytes:
    return n.to_bytes(4, 'big', signed=False)

######################################################################
# Grammar Rules
######################################################################

ctx.script('START', ['COMM_CHUNK_AIFF', 'SSND_CHUNK', 'EXTRA_LIST'], BUILD_AIFF)
ctx.script('START', ['FVER_CHUNK', 'COMM_CHUNK_AIFC', 'SSND_CHUNK', 'EXTRA_LIST'], BUILD_AIFC)
ctx.script('COMM_CHUNK_AIFF', ['CHANNELS', 'FRAMECOUNT', 'SAMPLEBITS', 'SAMPLERATE'], MK_COMM_AIFF)
ctx.script('COMM_CHUNK_AIFC', ['CHANNELS', 'FRAMECOUNT', 'SAMPLEBITS', 'SAMPLERATE', 'COMPTYPE', 'COMPNAME'], MK_COMM_AIFC)
ctx.literal('CHANNELS', b'\x00\x01')
ctx.literal('CHANNELS', b'\x00\x01')
ctx.bytes('CHANNELS', 2)
ctx.bytes('FRAMECOUNT', 4)
ctx.literal('SAMPLEBITS', b'\x00\x08')
ctx.literal('SAMPLEBITS', b'\x00\x08')
ctx.literal('SAMPLEBITS', b'\x00\x18')
ctx.literal('SAMPLERATE', bytes.fromhex('400EAC44000000000000'))
ctx.literal('SAMPLERATE', bytes.fromhex('400EBB80000000000000'))
ctx.literal('COMPTYPE', b'NONE')
ctx.literal('COMPTYPE', b'NONE')
ctx.literal('COMPTYPE', b'ulaw')
ctx.literal('COMPTYPE', b'ulaw')
ctx.bytes('COMPSTR10', 10)
ctx.bytes('COMPSTR10', 10)
ctx.rule('COMP_BUF', b'{COMPSTR10}')
ctx.rule('COMP_BUF', b'{COMPSTR10}')
ctx.script('COMPNAME', ['COMP_BUF'], lambda COMP_BUF: _pstr(COMP_BUF))
ctx.literal('VERSION', b'\xa2\x80Q@')
ctx.script('FVER_CHUNK', ['VERSION'], MK_FVER)
ctx.literal('OFFSET', b'\x00\x00\x00\x00')
ctx.literal('BLOCKSIZE', b'\x00\x00\x00\x00')
ctx.literal('AUDPAY', b'')
ctx.bytes('AUD32', 32)
ctx.bytes('AUD32', 32)
ctx.rule('AUDPAY', b'{AUD32}')
ctx.rule('AUDPAY', b'{AUD32}')
ctx.script('SSND_CHUNK', ['OFFSET', 'BLOCKSIZE', 'AUDPAY'], MK_SSND)
ctx.literal('EXTRA_LIST', b'')
ctx.rule('EXTRA_LIST', b'{EXTRA}')
ctx.rule('EXTRA_LIST', b'{EXTRA}{EXTRA}')
ctx.rule('EXTRA_LIST', b'{EXTRA}{EXTRA}{EXTRA}')
ctx.bytes('TXT12', 12)
ctx.bytes('TXT12', 12)
ctx.rule('TXT_CONTENT', b'{TXT12}')
ctx.rule('TXT_CONTENT', b'{TXT12}')
ctx.script('NAME_CHUNK', ['TXT_CONTENT'], lambda TXT_CONTENT: MK_TEXT(b'NAME', TXT_CONTENT))
ctx.script('AUTH_CHUNK', ['TXT_CONTENT'], lambda TXT_CONTENT: MK_TEXT(b'AUTH', TXT_CONTENT))
ctx.script('ANNO_CHUNK', ['TXT_CONTENT'], lambda TXT_CONTENT: MK_TEXT(b'ANNO', TXT_CONTENT))
ctx.literal('MC1', b'\x00\x01')
ctx.literal('MC1', b'\x00\x01')
ctx.rule('MARKCOUNT', b'{MC1}')
ctx.rule('MARKCOUNT', b'{MC1}')
ctx.bytes('MID', 2)
ctx.bytes('MID', 2)
ctx.bytes('MNAME4', 4)
ctx.bytes('MNAME4', 4)
ctx.rule('MNAME', b'{MNAME4}')
ctx.rule('MNAME', b'{MNAME4}')
ctx.script('MREC', ['MID', 'MPOS', 'MNAME'], MK_MARKER)
ctx.rule('MRECS', b'{MREC}')
ctx.rule('MRECS', b'{MREC}{MREC}')
ctx.script('MARK_CHUNK', ['MARKCOUNT', 'MRECS'], MK_MARK)
ctx.bytes('INSTDATA', 20)
ctx.bytes('INSTDATA', 20)
ctx.script('INST_CHUNK', ['INSTDATA'], lambda INSTDATA: MK_SIMPLE(b'INST', INSTDATA))
ctx.script('COMT_CHUNK', ['COMTDATA'], lambda COMTDATA: MK_SIMPLE(b'COMT', COMTDATA))
ctx.bytes('PROPDATA', 32)
ctx.bytes('PROPDATA', 32)
ctx.script('PROP_CHUNK', ['PROPDATA'], lambda PROPDATA: MK_SIMPLE(b'PROP', PROPDATA))
ctx.script('ID3_CHUNK', ['ID3DATA'], lambda ID3DATA: MK_SIMPLE(b'ID3 ', ID3DATA))
ctx.regex('FOURCC', '[A-Z0-9]{4}')
ctx.bytes('GD20', 20)
ctx.bytes('GD20', 20)
ctx.rule('GEN_DATA', b'{GD20}')
ctx.rule('GEN_DATA', b'{GD20}')
ctx.script('GEN_GOOD', ['FOURCC', 'GEN_DATA'], MK_UNKNOWN_GOOD)
ctx.script('GEN_BAD', ['FOURCC', 'GEN_DATA'], MK_UNKNOWN_BAD)
ctx.rule('EXTRA', b'{NAME_CHUNK}')
ctx.rule('EXTRA', b'{AUTH_CHUNK}')
ctx.rule('EXTRA', b'{ANNO_CHUNK}')
ctx.rule('EXTRA', b'{MARK_CHUNK}')
ctx.rule('EXTRA', b'{INST_CHUNK}')
ctx.rule('EXTRA', b'{COMT_CHUNK}')
ctx.rule('EXTRA', b'{PROP_CHUNK}')
ctx.rule('EXTRA', b'{ID3_CHUNK}')
ctx.rule('EXTRA', b'{GEN_GOOD}')
ctx.rule('EXTRA', b'{GEN_GOOD}')
ctx.rule('EXTRA', b'{GEN_GOOD}')
ctx.rule('EXTRA', b'{GEN_GOOD}')
ctx.rule('EXTRA', b'{GEN_BAD}')
