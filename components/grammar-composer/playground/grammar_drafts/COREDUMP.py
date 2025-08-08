######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{ELF_HEADER}{PROGRAM_HEADER}{NOTE_CONTENT}')
ctx.rule('ELF_HEADER', b'\x7fELF{EI_CLASS}{EI_DATA}\x01{OSABI}{ABIVERSION}\x00\x00\x00\x00\x00\x00\x00\x04\x00{MACHINE}\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{FLAGS}@\x008\x00\x01\x00\x00\x00\x00\x00\x00\x00')
ctx.rule('PROGRAM_HEADER', b'\x04\x00\x00\x00{PH_FLAGS}x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{P_FILESZ}{P_MEMSZ}\x04\x00\x00\x00\x00\x00\x00\x00')
ctx.rule('NOTE_CONTENT', b'{NOTE_ENTRY}{NOTE_CONTENT}')
ctx.rule('NOTE_CONTENT', b'{RND16}')
ctx.literal('NOTE_CONTENT', b'')
ctx.rule('NOTE_ENTRY', b'\x04\x00\x00\x00{DESC_SIZE}{NOTE_TYPE}CORE{DESC_DATA}')
ctx.literal('DESC_SIZE', b' \x00\x00\x00')
ctx.literal('DESC_SIZE', b'@\x00\x00\x00')
ctx.literal('DESC_SIZE', b'\x80\x00\x00\x00')
ctx.bytes('DESC32', 32)
ctx.bytes('DESC64', 64)
ctx.bytes('DESC128', 128)
ctx.rule('DESC_DATA', b'{DESC32}')
ctx.rule('DESC_DATA', b'{DESC64}')
ctx.rule('DESC_DATA', b'{DESC128}')
ctx.literal('NOTE_TYPE', b'\x01\x00\x00\x00')
ctx.literal('NOTE_TYPE', b'\x03\x00\x00\x00')
ctx.literal('NOTE_TYPE', b'\x06\x00\x00\x00')
ctx.literal('NOTE_TYPE', b'\x10\x00\x00\x00')
ctx.literal('EI_CLASS', b'\x01')
ctx.literal('EI_CLASS', b'\x02')
ctx.literal('EI_DATA', b'\x01')
ctx.literal('EI_DATA', b'\x02')
ctx.literal('OSABI', b'\x00')
ctx.literal('OSABI', b'\x03')
ctx.bytes('ABIVERSION', 1)
ctx.bytes('MACHINE', 2)
ctx.bytes('FLAGS', 4)
ctx.bytes('PH_FLAGS', 4)
ctx.bytes('P_FILESZ', 8)
ctx.bytes('P_MEMSZ', 8)
ctx.bytes('RND16', 16)
