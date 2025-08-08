######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

######################################################################
# Grammar Rules
######################################################################

ctx.literal('MAGIC', b'\x00asm')
ctx.literal('VERSION', b'\x01\x00\x00\x00')
ctx.rule('START', b'{MAGIC}{VERSION}{MODULE}')
ctx.rule('MODULE', b'{VALID_BUNDLES}{FUZZ_SECTIONS}')
ctx.rule('VALID_BUNDLES', b'{VALID_BUNDLE}{VALID_BUNDLES}')
ctx.literal('VALID_BUNDLES', b'')
ctx.literal('BUNDLE_VOID', b'\x01\x04\x01`\x00\x00\x03\x02\x01\x00\n\x04\x01\x02\x00\x0b')
ctx.literal('BUNDLE_RET_I32', b'\x01\x05\x01`\x00\x01\x7f\x03\x02\x01\x00\n\x06\x01\x04\x00A*\x0b')
ctx.literal('BUNDLE_ADD_I32', b'\x01\x05\x01`\x00\x01\x7f\x03\x02\x01\x00\n\x0b\x01\t\x00A*A\x15j\x0b')
ctx.rule('VALID_BUNDLE', b'{BUNDLE_VOID}')
ctx.rule('VALID_BUNDLE', b'{BUNDLE_RET_I32}')
ctx.rule('VALID_BUNDLE', b'{BUNDLE_ADD_I32}')
ctx.rule('FUZZ_SECTIONS', b'{SECTION}{FUZZ_SECTIONS}')
ctx.literal('FUZZ_SECTIONS', b'')
ctx.rule('SECTION', b'{MEMORY_SECTION_MIN}')
ctx.rule('SECTION', b'{GLOBAL_SECTION_I32_42}')
ctx.rule('SECTION', b'{EXPORT_SECTION_FUNC0}')
ctx.rule('SECTION', b'{IMPORT_SECTION_FUNC}')
ctx.rule('SECTION', b'{DATA_SECTION_ZERO}')
ctx.rule('SECTION', b'{CUSTOM_SECTION_SMALL}')
ctx.rule('SECTION', b'{CUSTOM_SECTION_RANDOM}')
ctx.rule('SECTION', b'{DUPLICATE_TYPE_SECTION}')
ctx.rule('SECTION', b'{BAD_ID13_SECTION}')
ctx.rule('SECTION', b'{RANDOM_ID_SECTION}')
ctx.rule('SECTION', b'{MIS_SIZE_SECTION}')
ctx.literal('MEMORY_SECTION_MIN', b'\x05\x03\x01\x00\x01')
ctx.literal('GLOBAL_SECTION_I32_42', b'\x06\x06\x01\x7f\x00A*\x0b')
ctx.literal('EXPORT_SECTION_FUNC0', b'\x07\x05\x01\x01f\x00\x00')
ctx.literal('IMPORT_SECTION_FUNC', b'\x02\x07\x01\x01m\x01f\x00\x00')
ctx.literal('DATA_SECTION_ZERO', b'\x0b\x07\x01\x00A\x00\x0b\x01\x00')
ctx.literal('DUPLICATE_TYPE_SECTION', b'\x01\x01\x00')
ctx.literal('CUSTOM_SECTION_SMALL', b'\x00\x01\x00')
ctx.bytes('RAND1', 1)
ctx.bytes('RAND2', 2)
ctx.bytes('RAND4', 4)
ctx.rule('CUSTOM_SECTION_RANDOM', b'\x00\x03\x01A{RAND1}')
ctx.rule('BAD_ID13_SECTION', b'\r\x01{RAND1}')
ctx.rule('RANDOM_ID_SECTION', b'{RAND1}\x01{RAND1}')
ctx.rule('MIS_SIZE_SECTION', b'\x01\xff{RAND1}')
