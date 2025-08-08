######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{PE_HEADER}{TEXT_SECTION}{OVERLAY}')
ctx.rule('PE_HEADER', b'{DOS_HEADER}{DOS_STUB}{PE_SIG}{COFF_HEADER}{OPTIONAL_HEADER}{SECTION_HEADER}{HEADER_PAD}')
ctx.literal('DOS_HEADER', b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00')
ctx.rule('DOS_STUB', b'{STUB_MSG}{STUB_PAD}')
ctx.regex('STUB_MSG', '[ -~]{40}')
ctx.literal('STUB_PAD', b'\x00' * 24)
ctx.literal('PE_SIG', b'PE\x00\x00')
ctx.rule('COFF_HEADER', b'L\x01\x01\x00{TIMESTAMP}\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00{CHARACTERISTICS}')
ctx.bytes('TIMESTAMP', 4)
ctx.literal('CHARACTERISTICS', b'\x02\x01')
ctx.literal('CHARACTERISTICS', b'"\x01')
ctx.rule('OPTIONAL_HEADER', b'{OPT_PREFIX}{SUBSYSTEM}{DLL_CHARS}{OPT_SUFFIX}')
ctx.literal('OPT_PREFIX', b'\x0b\x01\x06\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00 \x00\x00\x00\x00@\x00\x00\x10\x00\x00\x00\x02\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x02\x00\x00\x00\x00\x00\x00')
ctx.literal('SUBSYSTEM', b'\x03\x00')
ctx.literal('SUBSYSTEM', b'\x02\x00')
ctx.literal('DLL_CHARS', b'\x00\x00')
ctx.literal('DLL_CHARS', b'@\x01')
ctx.literal('OPT_SUFFIX', b'\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00' + b'\x00' * 128)
ctx.literal('SECTION_HEADER', b'.text\x00\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00`')
ctx.literal('HEADER_PAD', b'\x00' * 96)
ctx.bytes('TEXT_SECTION', 512)
ctx.rule('OVERLAY', b'{OVL_CHUNK}{OVERLAY}')
ctx.literal('OVERLAY', b'')
ctx.rule('OVL_CHUNK', b'{OVL32}')
ctx.rule('OVL_CHUNK', b'{OVL128}')
ctx.rule('OVL_CHUNK', b'{OVL512}')
ctx.bytes('OVL32', 32)
ctx.bytes('OVL128', 128)
ctx.bytes('OVL512', 512)
