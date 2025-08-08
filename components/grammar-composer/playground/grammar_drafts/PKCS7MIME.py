######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def good_b64(SMIME_TYPE: bytes, FILENAME: bytes, PKCS7_RAW: bytes, NL: bytes) -> bytes:
    import base64
    enc = base64.b64encode(PKCS7_RAW)
    wrapped = NL.join((enc[i:i + 64] for i in range(0, len(enc), 64))) + NL
    return b'Content-Type: application/pkcs7-mime; smime-type=' + SMIME_TYPE + b'; name="' + FILENAME + b'"' + NL + b'Content-Transfer-Encoding: base64' + NL + NL + wrapped

def good_qp(SMIME_TYPE: bytes, FILENAME: bytes, PKCS7_RAW: bytes, NL: bytes) -> bytes:
    import quopri
    qp = quopri.encodestring(PKCS7_RAW)
    return b'Content-Type: application/pkcs7-mime; smime-type=' + SMIME_TYPE + b'; name="' + FILENAME + b'"' + NL + b'Content-Transfer-Encoding: quoted-printable' + NL + NL + qp + NL

######################################################################
# Grammar Rules
######################################################################

ctx.literal('CRLF', b'\r\n')
ctx.literal('LF', b'\n')
ctx.rule('NL', b'{CRLF}')
ctx.rule('NL', b'{LF}')
ctx.literal('SP', b'')
ctx.literal('SP', b' ')
ctx.literal('SP', b'\t')
ctx.literal('ENCODING_TYPE', b'base64')
ctx.literal('ENCODING_TYPE', b'quoted-printable')
ctx.literal('ENCODING_TYPE', b'BINARY')
ctx.literal('ENCODING_TYPE', b'7bit')
ctx.literal('SMIME_TYPE', b'signed-data')
ctx.literal('SMIME_TYPE', b'enveloped-data')
ctx.literal('SMIME_TYPE', b'digested-data')
ctx.literal('SMIME_TYPE', b'compressed-data')
ctx.literal('SMIME_TYPE', b'certs-only')
ctx.regex('BASENAME', '[A-Za-z0-9]{1,16}')
ctx.literal('EXT', b'.p7m')
ctx.rule('FILENAME', b'{BASENAME}{EXT}')
ctx.regex('BOUNDARY', '[A-Za-z0-9]{12,60}')
ctx.regex('TXT', '[A-Za-z0-9]{0,40}')
ctx.literal('HNAME', b'Subject')
ctx.literal('HNAME', b'subject')
ctx.literal('HNAME', b'From')
ctx.literal('HNAME', b'X-Header')
ctx.literal('HNAME', b'TO')
ctx.rule('HFOLD', b'{CRLF} {TXT}')
ctx.literal('HFOLD', b'')
ctx.rule('HLINE', b'{HNAME}{SP}:{SP}{TXT}{HFOLD}{NL}')
ctx.literal('HEADERS', b'')
ctx.rule('HEADERS', b'{HLINE}')
ctx.rule('HEADERS', b'{HLINE}{HLINE}')
ctx.rule('HEADERS', b'{HLINE}{HLINE}{HLINE}')
ctx.rule('HEADERS', b'{HLINE}{HLINE}{HLINE}{HLINE}')
ctx.rule('HEADERS', b'{HLINE}{HLINE}{HLINE}{HLINE}{HLINE}')
ctx.literal('ASN1_MIN', b'0\x0b\x06\t*\x86H\x86\xf7\r\x01\x07\x01')
ctx.bytes('DER32', 32)
ctx.bytes('DER256', 256)
ctx.bytes('DER2K', 2048)
ctx.bytes('DER64', 64)
ctx.rule('DER_CHUNK', b'{ASN1_MIN}')
ctx.rule('DER_CHUNK', b'0{DER32}')
ctx.rule('DER_CHUNK', b'0\x82\x01\x00{DER256}')
ctx.rule('DER_CHUNK', b'0\x82\x08\x00{DER2K}')
ctx.rule('DER_CHUNK', b'0\x80{DER64}\x00\x00')
ctx.rule('PKCS7_RAW', b'{DER_CHUNK}')
ctx.rule('PKCS7_RAW', b'{DER_CHUNK}{DER_CHUNK}')
ctx.rule('INNER', b'Content-Type:{SP}application/pkcs7-mime;{SP}smime-type={SMIME_TYPE};{SP}name="{FILENAME}"{NL}Content-Transfer-Encoding:{SP}{ENCODING_TYPE}{NL}{NL}{PKCS7_RAW}{NL}')
ctx.script('GOOD_B64', ['SMIME_TYPE', 'FILENAME', 'PKCS7_RAW', 'NL'], good_b64)
ctx.script('GOOD_QP', ['SMIME_TYPE', 'FILENAME', 'PKCS7_RAW', 'NL'], good_qp)
ctx.rule('GOOD_BIN', b'Content-Type: application/pkcs7-mime; smime-type={SMIME_TYPE}; name="{FILENAME}"{NL}Content-Transfer-Encoding: binary{NL}{NL}{PKCS7_RAW}{NL}')
ctx.rule('MP_PREAMBLE', b'This is a multipart S/MIME.{NL}{NL}')
ctx.rule('MP_SIGNED_GOOD', b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="{BOUNDARY}"{NL}{NL}{MP_PREAMBLE}--{BOUNDARY}{NL}{INNER}--{BOUNDARY}{NL}{INNER}--{BOUNDARY}--{NL}')
ctx.rule('MP_MIXED_GOOD', b'Content-Type: multipart/mixed; boundary="{BOUNDARY}"{NL}{NL}--{BOUNDARY}{NL}{MP_SIGNED_GOOD}--{BOUNDARY}--{NL}')
ctx.rule('BAD_B64', b'Content-Type: application/pkcs7-mime; smime-type={SMIME_TYPE}; name="{FILENAME}"{NL}Content-Transfer-Encoding: base64{NL}{NL}{PKCS7_RAW}= {NL}')
ctx.rule('MP_SIGNED_TRUNC', b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-1; boundary="{BOUNDARY}"{NL}{NL}--{BOUNDARY}{NL}{INNER}--{BOUNDARY}{NL}{INNER}{NL}')
ctx.rule('BODY', b'{GOOD_B64}')
ctx.rule('BODY', b'{GOOD_B64}')
ctx.rule('BODY', b'{GOOD_QP}')
ctx.rule('BODY', b'{GOOD_BIN}')
ctx.rule('BODY', b'{MP_SIGNED_GOOD}')
ctx.rule('BODY', b'{MP_MIXED_GOOD}')
ctx.rule('BODY', b'{GOOD_B64}')
ctx.rule('BODY', b'{GOOD_BIN}')
ctx.rule('BODY', b'{BAD_B64}')
ctx.rule('BODY', b'{MP_SIGNED_TRUNC}')
ctx.rule('START', b'MIME-Version:{SP}1.0{NL}{HEADERS}{BODY}')
