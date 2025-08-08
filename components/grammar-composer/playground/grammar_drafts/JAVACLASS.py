######################################################################
# Helper Functions
######################################################################

def artiphishell_base64_encode(data: bytes) -> bytes:
    import base64
    return base64.b64encode(data)

def build_class_file(MINOR_VERSION: bytes, MAJOR_VERSION: bytes, CLASS_NAME: bytes, METHOD_NAME: bytes, BYTECODE: bytes) -> bytes:
    import struct, random
    code_len = random.randint(1, len(BYTECODE))
    code = BYTECODE[:code_len]
    magic = b'\xca\xfe\xba\xbe'
    cp1 = b'\x01' + struct.pack('>H', len(CLASS_NAME)) + CLASS_NAME
    cp2 = b'\x07\x00\x01'
    parent = b'java/lang/Object'
    cp3 = b'\x01' + struct.pack('>H', len(parent)) + parent
    cp4 = b'\x07\x00\x03'
    cp5 = b'\x01' + struct.pack('>H', len(METHOD_NAME)) + METHOD_NAME
    desc = b'()V'
    cp6 = b'\x01\x00\x03()V'
    cp7 = b'\x0c\x00\x05\x00\x06'
    cp8 = b'\x01\x00\x04Code'
    constant_pool = struct.pack('>H', 9) + cp1 + cp2 + cp3 + cp4 + cp5 + cp6 + cp7 + cp8
    access_flags = b'\x00!'
    this_class = b'\x00\x02'
    super_class = b'\x00\x04'
    interfaces_cnt = b'\x00\x00'
    fields_cnt = b'\x00\x00'
    meth_access = b'\x00\x01'
    meth_name_idx = b'\x00\x05'
    meth_desc_idx = b'\x00\x06'
    meth_attr_cnt = b'\x00\x01'
    attr_name_idx = b'\x00\x08'
    max_stack = b'\x00\x02'
    max_locals = b'\x00\x01'
    exc_table_len = b'\x00\x00'
    code_attr_attr_cnt = b'\x00\x00'
    code_attribute = attr_name_idx + struct.pack('>I', 12 + code_len) + max_stack + max_locals + struct.pack('>I', code_len) + code + exc_table_len + code_attr_attr_cnt
    method_info = meth_access + meth_name_idx + meth_desc_idx + meth_attr_cnt + code_attribute
    methods_cnt = b'\x00\x01'
    class_attr_cnt = b'\x00\x00'
    class_file = magic + MINOR_VERSION + MAJOR_VERSION + constant_pool + access_flags + this_class + super_class + interfaces_cnt + fields_cnt + methods_cnt + method_info + class_attr_cnt
    return class_file

######################################################################
# Grammar Rules
######################################################################

ctx.rule('START', b'{CLASS_FILE}')
ctx.bytes('MINOR_VERSION', 2)
ctx.bytes('MAJOR_VERSION', 2)
ctx.regex('CLASS_NAME', '[A-Za-z_$][A-Za-z0-9/_$]{0,31}')
ctx.regex('METHOD_NAME', '[a-zA-Z_$][A-Za-z0-9_$]{0,7}')
ctx.bytes('BYTECODE', 16)
ctx.script('CLASS_FILE', ['MINOR_VERSION', 'MAJOR_VERSION', 'CLASS_NAME', 'METHOD_NAME', 'BYTECODE'], build_class_file)
