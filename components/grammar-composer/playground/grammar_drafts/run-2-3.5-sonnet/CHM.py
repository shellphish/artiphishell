######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.literal('ITSF_SIG', b'ITSF')
ctx.literal('ITSP_SIG', b'ITSP')
ctx.literal('LZXC_SIG', b'LZXC')
ctx.literal('VERSION3', b'\x03\x00\x00\x00')
ctx.literal('HEADER_LEN', b'`\x00\x00\x00')
ctx.literal('LANG_EN', b'\t\x04\x00\x00')
ctx.literal('DIR_OFFSET', b'\x00\x10\x00\x00')
ctx.literal('DIR_LEN', b'\x00 \x00\x00')
ctx.literal('SYSTEM_FILE', b'/#SYSTEM\x00')
ctx.literal('STRINGS_FILE', b'/#STRINGS\x00')
ctx.literal('WINDOWS_FILE', b'/#WINDOWS\x00')
ctx.literal('TOPICS_FILE', b'/#TOPICS\x00')
ctx.literal('URLTBL_FILE', b'/#URLTBL\x00')
ctx.literal('URLSTR_FILE', b'/#URLSTR\x00')
ctx.literal('ZEROS_32', b'\x00\x00\x00\x00')
ctx.rule('ITSF_HEADER', b'{ITSF_SIG}{VERSION3}{HEADER_LEN}{LANG_EN}{ZEROS_32}{ZEROS_32}{DIR_OFFSET}{DIR_LEN}{ZEROS_32}')
ctx.literal('BLOCK_SIZE', b'\x00\x10\x00\x00')
ctx.literal('DENSITY', b'\x02\x00')
ctx.literal('DEPTH', b'\x01\x00')
ctx.literal('ROOT_CHUNK', b'\x00\x00\x00\x00')
ctx.literal('FIRST_PMG', b'\x00\x00\x00\x00')
ctx.literal('LAST_PMG', b'\xff\xff\xff\xff')
ctx.rule('ITSP_HEADER', b'{ITSP_SIG}{VERSION3}{DIR_LEN}{BLOCK_SIZE}{DENSITY}{DEPTH}{ROOT_CHUNK}{FIRST_PMG}{LAST_PMG}')
ctx.literal('OFFSET_1', b'\x000\x00\x00')
ctx.literal('OFFSET_2', b'\x00@\x00\x00')
ctx.literal('OFFSET_3', b'\x00P\x00\x00')
ctx.literal('OFFSET_4', b'\x00`\x00\x00')
ctx.literal('OFFSET_5', b'\x00p\x00\x00')
ctx.literal('OFFSET_6', b'\x00\x80\x00\x00')
ctx.literal('LENGTH_STD', b'\x00\x10\x00\x00')
ctx.literal('FLAG_COMPRESSED', b'\x02\x00')
ctx.rule('SYSTEM_ENTRY', b'{OFFSET_1}{LENGTH_STD}{FLAG_COMPRESSED}{SYSTEM_FILE}')
ctx.rule('STRINGS_ENTRY', b'{OFFSET_2}{LENGTH_STD}{FLAG_COMPRESSED}{STRINGS_FILE}')
ctx.rule('WINDOWS_ENTRY', b'{OFFSET_3}{LENGTH_STD}{FLAG_COMPRESSED}{WINDOWS_FILE}')
ctx.rule('TOPICS_ENTRY', b'{OFFSET_4}{LENGTH_STD}{FLAG_COMPRESSED}{TOPICS_FILE}')
ctx.rule('URLTBL_ENTRY', b'{OFFSET_5}{LENGTH_STD}{FLAG_COMPRESSED}{URLTBL_FILE}')
ctx.rule('URLSTR_ENTRY', b'{OFFSET_6}{LENGTH_STD}{FLAG_COMPRESSED}{URLSTR_FILE}')
ctx.rule('DIR_ENTRIES', b'{SYSTEM_ENTRY}{STRINGS_ENTRY}{WINDOWS_ENTRY}{TOPICS_ENTRY}{URLTBL_ENTRY}{URLSTR_ENTRY}')
ctx.literal('CONTENT_SIZE', b'\x00\x08\x00\x00')
ctx.bytes('CONTENT_DATA', 32)
ctx.rule('FILE_CONTENT', b'{LZXC_SIG}{VERSION3}{CONTENT_SIZE}{CONTENT_DATA}')
ctx.rule('FILE_CONTENTS', b'{FILE_CONTENT}{FILE_CONTENT}{FILE_CONTENT}{FILE_CONTENT}{FILE_CONTENT}{FILE_CONTENT}')
ctx.rule('START', b'{ITSF_HEADER}{ITSP_HEADER}{DIR_ENTRIES}{FILE_CONTENTS}')
