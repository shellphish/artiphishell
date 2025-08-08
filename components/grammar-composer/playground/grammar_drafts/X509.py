######################################################################
# Helper Functions
######################################################################

def _alg_identifier() -> bytes:
    oid = _tlv(6, b'*\x86H\x86\xf7\r\x01\x01\x01')
    null = b'\x05\x00'
    return _tlv(48, oid + null)

def _basic_constraints_ext(caflag_byte: bytes) -> bytes:
    bc_seq = _tlv(48, b'\x01\x01' + caflag_byte)
    bc_oct = _tlv(4, bc_seq)
    oid_bc = _tlv(6, b'U\x1d\x13')
    ext = _tlv(48, oid_bc + bc_oct)
    extensions = _tlv(48, ext)
    return bytes([163]) + _enc_len(len(extensions)) + extensions

def _bit_string(payload: bytes) -> bytes:
    return _tlv(3, b'\x00' + payload)

def _enc_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    if n < 256:
        return b'\x81' + bytes([n])
    if n < 65536:
        return b'\x82' + bytes([n >> 8 & 255, n & 255])
    return b'\x83' + bytes([n >> 16 & 255, n >> 8 & 255, n & 255])

def _int_tlv(int_bytes: bytes) -> bytes:
    if int_bytes and int_bytes[0] & 128:
        int_bytes = b'\x00' + int_bytes
    return _tlv(2, int_bytes)

def _name(common_name: bytes) -> bytes:
    oid_cn = _tlv(6, b'U\x04\x03')
    val_cn = _tlv(19, common_name)
    atv = _tlv(48, oid_cn + val_cn)
    set_rdn = _tlv(49, atv)
    return _tlv(48, set_rdn)

def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content

def _utc_time(ts: bytes) -> bytes:
    return _tlv(23, ts)

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_certificate(SERIAL_BYTES: bytes, MODULUS: bytes, SIGNATURE_BYTES: bytes, CN_VAL: bytes, NOT_BEFORE: bytes, CAFLAG: bytes) -> bytes:
    version = b'\xa0\x03\x02\x01\x02'
    serial = _int_tlv(b'\x00' + SERIAL_BYTES)
    alg_id = _alg_identifier()
    issuer = _name(CN_VAL)
    subject = issuer
    not_after_const = b'991231235959Z'
    validity = _tlv(48, _utc_time(NOT_BEFORE) + _utc_time(not_after_const))
    exponent = _int_tlv(b'\x01\x00\x01')
    rsa_key = _tlv(48, _int_tlv(MODULUS) + exponent)
    spki = _tlv(48, alg_id + _bit_string(rsa_key))
    extensions = _basic_constraints_ext(CAFLAG)
    tbs = _tlv(48, version + serial + alg_id + issuer + validity + subject + spki + extensions)
    signature = _bit_string(SIGNATURE_BYTES)
    cert = _tlv(48, tbs + alg_id + signature)
    return cert

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{CERT}')
ctx.bytes('SERIAL_1', 1)
ctx.bytes('SERIAL_4', 4)
ctx.bytes('SERIAL_8', 8)
ctx.rule('SERIAL_BYTES', b'{SERIAL_1}')
ctx.rule('SERIAL_BYTES', b'{SERIAL_4}')
ctx.rule('SERIAL_BYTES', b'{SERIAL_8}')
ctx.regex('CN_VAL', '[A-Za-z0-9]{1,32}')
ctx.regex('NOT_BEFORE', '2[0-4][0-9][0-1][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]Z')
ctx.bytes('MOD64', 64)
ctx.bytes('MOD128', 128)
ctx.bytes('MOD256', 256)
ctx.rule('MODULUS', b'{MOD64}')
ctx.rule('MODULUS', b'{MOD128}')
ctx.rule('MODULUS', b'{MOD256}')
ctx.bytes('SIG64', 64)
ctx.bytes('SIG128', 128)
ctx.bytes('SIG256', 256)
ctx.rule('SIGNATURE_BYTES', b'{SIG64}')
ctx.rule('SIGNATURE_BYTES', b'{SIG128}')
ctx.rule('SIGNATURE_BYTES', b'{SIG256}')
ctx.literal('CAFLAG', b'\x00')
ctx.literal('CAFLAG', b'\xff')
ctx.script('CERT', ['SERIAL_BYTES', 'MODULUS', 'SIGNATURE_BYTES', 'CN_VAL', 'NOT_BEFORE', 'CAFLAG'], build_certificate)
