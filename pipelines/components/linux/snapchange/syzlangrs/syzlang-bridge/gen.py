"""
larkvm ~ syzlang-brige/gen.py
Converts json syzlang descriptions into descriptions usable by larkvm
"""

import json

def type_from_arg(syzlang, arg):
    type_obj = syzlang['Types'][arg['Type']]
    type_enum = type_obj['Name'][:-4]
    return f"types::Type::{type_enum}(types::gen::type_{arg['Type']})"

def elem_type_from_type_obj(syzlang, ptr):
    type_obj = syzlang['Types'][ptr['Value']['Elem']]
    type_enum = type_obj['Name'][:-4]
    return f"&Type::{type_enum}(type_{ptr['Value']['Elem']})"

def field_type_from_field_obj(syzlang, field):
    type_obj = syzlang['Types'][field['Type']]
    type_enum = type_obj['Name'][:-4]
    return f"&Type::{type_enum}(type_{field['Type']})"

def ret_type_from_syscall(syzlang, syscall):
    ret_type_id = syscall['Ret']
    if ret_type_id is None: return "None"

    type_obj = syzlang['Types'][ret_type_id]
    type_enum = type_obj['Name'][:-4]
    return f"Some(types::Type::{type_enum}(types::gen::type_{syscall['Ret']}))"

def format_type_generic(type_obj):
    out = ""
    type_name = type_obj['Value']['TypeName']
    type_name = type_name.replace("\"", "\\\"")
    out += f"\tname: \"{type_name}\",\n"
    out += f"\tsize: {type_obj['Value']['TypeSize']},\n"
    out += f"\talign: {type_obj['Value']['TypeAlign']},\n"
    return out

def arg_format_name(arg_format):
    match arg_format:
        case 0: return "BinaryFormat::FormatNative"
        case 1: return "BinaryFormat::FormatBigEndian"
        case 2: return "BinaryFormat::FormatStrDec"
        case 3: return "BinaryFormat::FormatStrHex"
        case 4: return "BinaryFormat::FormatStrOct"
        case _:
            raise Exception("Unreachable")

def format_int_type(type_obj):
    kind_id = type_obj['Value']['Kind']

    if kind_id == 0:
        kind = 'IntKind::IntPlain'
    elif kind_id == 1:
        kind = f"IntKind::IntRange({type_obj['Value']['RangeBegin']}, {type_obj['Value']['RangeEnd']})"
    else:
        raise Exception("Unreachable")

    out = format_type_generic(type_obj)
    out += f"\tkind: {kind},\n"
    out += f"\targ_format: {arg_format_name(type_obj['Value']['ArgFormat'])},\n"
    out += f"\tbitfield_len: {type_obj['Value']['BitfieldLen']},\n"
    out += f"\tbitfield_off: {type_obj['Value']['BitfieldOff']},\n"
    return out

def format_const_type(type_obj):
    out = format_type_generic(type_obj)
    out += f"\tval: {type_obj['Value']['Val']},\n"
    out += f"\targ_format: {arg_format_name(type_obj['Value']['ArgFormat'])},\n"
    out += f"\tbitfield_len: {type_obj['Value']['BitfieldLen']},\n"
    out += f"\tbitfield_off: {type_obj['Value']['BitfieldOff']},\n"

    is_pad = type_obj['Value']['IsPad'] == True
    is_pad = "true" if is_pad else "false"
    out += f"\tis_pad: {is_pad},\n"
    return out

def format_flags_type(type_obj):
    out = format_type_generic(type_obj)
    out += f"\tvals: &{type_obj['Value']['Vals']},\n"
    out += f"\targ_format: {arg_format_name(type_obj['Value']['ArgFormat'])},\n"
    out += f"\tbitfield_len: {type_obj['Value']['BitfieldLen']},\n"
    out += f"\tbitfield_off: {type_obj['Value']['BitfieldOff']},\n"
    return out

def resource_by_name(syzlang, resource_name):
    return [(idx, r) for idx, r in enumerate(syzlang['Resources']) if r['Name'] == resource_name][0]

def format_resource_type(type_obj):
    out = format_type_generic(type_obj)
    resource_name = type_obj['Value']['TypeName']
    out += f"\tdesc: resources::gen::rsrc_{resource_name},\n"
    out += f"\targ_format: {arg_format_name(type_obj['Value']['ArgFormat'])},\n"
    return out

def format_ptr_type(syzlang, type_obj):
    out = format_type_generic(type_obj)
    out += f"\telem: {elem_type_from_type_obj(syzlang, type_obj)},\n"
    direction = ['DirIn', 'DirOut', 'DirInOut'][type_obj['Value']['ElemDir']]
    out += f"\tdir: Dir::{direction}\n"
    return out

def format_len_type(syzlang, type_obj):
    out = format_type_generic(type_obj)
    path = str(type_obj['Value']['Path']).replace("\'", "\"")
    out += f"\targ_format: {arg_format_name(type_obj['Value']['ArgFormat'])},\n"
    out += f"\tbitfield_len: {type_obj['Value']['BitfieldLen']},\n"
    out += f"\tbitfield_off: {type_obj['Value']['BitfieldOff']},\n"
    out += f"\toffset: false,\n"
    out += f"\tpath: &{path}\n"
    return out

def formatted_to_bytes(formatted):
    out = b""
    for e in formatted:
        if isinstance(e, str):
            out += e.encode()
        else:
            out += e
    return out


def format_buffer_type(type_obj):
    kinds = [
        "BufferBlobRand",
        "BufferBlobRange",
        "BufferString",
        "BufferFilename",
        "BufferText",
        "BufferGlob",
        "BufferCompressed"
    ]
    kind = kinds[type_obj['Value']['Kind']]

    values = type_obj['Value']['Values']
    if values is None:
        values = b""
    else:
        values = b", ".join([b"\""+(v.encode('utf-8').replace(b"\\", b"\\\\").replace(b"\r", b"\\r").replace(b"\"", b"\\\"").replace(b"\'", b"\\\'")) + b"\"" for v in type_obj['Value']['Values']])
        #print(values)

    noz = kinds[type_obj['Value']['NoZ']] == True
    noz = "true" if noz else "false"

    varlen = kinds[type_obj['Value']['IsVarlen']] == True
    varlen = "true" if varlen else "false"

    out = []
    out += [format_type_generic(type_obj)]
    out += [f"\tkind: BufferKind::{kind},\n"]
    out += [f"\tis_varlen: {varlen},\n"]
    out += [b"\tvalues: &[" + values + b"],\n"]
    out += [f"\trange_begin: {type_obj['Value']['RangeBegin']},\n"]
    out += [f"\trange_end: {type_obj['Value']['RangeEnd']},\n"]
    out += [f"\tnoz: {noz},\n"]
    return formatted_to_bytes(out).decode()

def format_array_type(syzlang, type_obj):
    kind_val = type_obj['Value']['Kind']
    if kind_val == 0:
        kind = "ArrayRandLen"
    elif kind_val == 1:
        kind = f"ArrayRangeLen({type_obj['Value']['RangeBegin']}, {type_obj['Value']['RangeEnd']})"
    else:
        raise Exception(type_obj)

    varlen = type_obj['Value']['IsVarlen'] == True
    varlen = "true" if varlen else "false"

    out = format_type_generic(type_obj)
    out += f"\tkind: ArrayKind::{kind},\n"
    out += f"\tis_varlen: {varlen},\n"
    out += f"\telem: {elem_type_from_type_obj(syzlang, type_obj)}\n"
    return out

def format_struct_type(syzlang, type_obj):
    out = format_type_generic(type_obj)
    fields = []
    for field in type_obj['Value']['Fields']:
        field_out = ""
        field_out += f"\t\t\tname: \"{field['Name']}\",\n"
        field_out += f"\t\t\ttyp: FieldType::Index({field['Type']}),\n"
        field_out += f"\t\t\thas_dir: {str(field['HasDirection']).lower()},\n"
        direction = ['DirIn', 'DirOut', 'DirInOut'][field['Direction']]
        field_out += f"\t\t\tdir: Dir::{direction},\n"
        field_out = f"\t\tField {{\n{field_out}\t\t}}"
        fields += [field_out]
    fields = ",\n".join(fields)

    out += f"\tfields: &[\n{fields}\n\t],\n"
    return out

def format_union_type(syzlang, type_obj):
    out = format_type_generic(type_obj)

    fields = []
    for field in type_obj['Value']['Fields']:
        field_out = ""
        field_out += f"\t\t\tname: \"{field['Name']}\",\n"
        field_out += f"\t\t\ttyp: FieldType::Index({field['Type']}),\n"
        field_out += f"\t\t\thas_dir: {str(field['HasDirection']).lower()},\n"
        direction = ['DirIn', 'DirOut', 'DirInOut'][field['Direction']]
        field_out += f"\t\t\tdir: Dir::{direction},\n"
        field_out = f"\t\tField {{\n{field_out}\t\t}}"
        fields += [field_out]
    fields = ",\n".join(fields)

    out += f"\tfields: &[\n{fields}\n\t],\n"
    varlen = type_obj['Value']['IsVarlen'] == True
    varlen = "true" if varlen else "false"
    out += f"\tvarlen: {varlen},\n"
    return out

def format_type(syzlang, type_id):
    type_obj = syzlang['Types'][type_id]
    match type_obj['Name']:
        case "IntType":
            return format_int_type(type_obj)
        case "ConstType":
            return format_const_type(type_obj)
        case "FlagsType":
            return format_flags_type(type_obj)
        case "ResourceType":
            return format_resource_type(type_obj)
        case "PtrType":
            return format_ptr_type(syzlang, type_obj)
        case "LenType":
            return format_len_type(syzlang, type_obj)
        case "BufferType":
            return format_buffer_type(type_obj)
        case "ArrayType":
            return format_array_type(syzlang, type_obj)
        case "StructType":
            return format_struct_type(syzlang, type_obj)
        case "UnionType":
            return format_union_type(syzlang, type_obj)
        case "VmaType":
            # TODO
            return ""
        case "ProcType":
            # TODO
            return ""
        case "CsumType":
            # TODO
            return ""
    raise Exception("TODO", type_obj)

def gen_type_desc(syzlang, type_id, type_obj):
    type_enum = type_obj['Name'][:-4] # Strip 'Type' from the end

    type_def = ""
    type_def += f"pub const type_{type_id}: {type_enum} = {type_enum} {{\n" # }}
    type_def += format_type(syzlang, type_id)
    type_def += "};\n\n"
    return type_def

def gen_resource_desc(resource_obj, resource_idx):
    resource_def = ""
    resource_def += f"pub const rsrc_{resource_obj['Name']}: ResourceDesc = ResourceDesc {{\n" # }}
    resource_def += f"\tid: {resource_idx},\n"
    resource_kind = ", ".join(["rsrc_"+rsrc for rsrc in resource_obj['Kind'] if rsrc != resource_obj['Name']])
    resource_def += f"\tkind: &[{resource_kind}]\n"
    resource_def += "};\n"
    return resource_def

def gen_syscall_desc(syzlang, syscall):
    syscall_def = ""
    syscall_def += "SyscallDef {\n" # }
    syscall_def += f"\t\tid: {syscall['NR']},\n"
    syscall_def += f"\t\tname: \"{syscall['Name']}\",\n"
    syscall_def += f"\t\targs: &[\n" # ]

    if not syscall['Args'] is None:
        for arg in syscall['Args']:
            arg_type = f"(\"{arg['Name']}\", {type_from_arg(syzlang, arg)})"
            syscall_def += f"\t\t\t{arg_type},\n"

    syscall_def += "\t\t],\n"
    syscall_def += f"\t\tret: {ret_type_from_syscall(syzlang, syscall)}\n"
    syscall_def += "\t},\n"
    return syscall_def

def main():
    with open("./syzkaller/sys/json/linux/amd64.json") as fp:
        syzlang = json.load(fp)

    proj_src_path = "../src/"
    resources_path = "grammar/resources/gen.rs"
    resource_gen = ""
    resource_gen += "#![allow(non_upper_case_globals)]\n"
    resource_gen += "// THIS FILE IS AUTOGENERATED BY SYZLANG-BRIDGE\n"
    resource_gen += "use crate::grammar::resources::ResourceDesc;\n\n"

    for idx, resource_obj in enumerate(syzlang['Resources']):
        resource_gen += gen_resource_desc(resource_obj, idx)

    with open(proj_src_path+resources_path, "w") as fp:
        fp.write(resource_gen)

    types_path = "grammar/types/gen.rs"
    types_gen = ""
    types_gen += "#![allow(non_upper_case_globals)]\n"
    types_gen += "#![allow(dead_code)]\n"
    types_gen += "// THIS FILE IS AUTOGENERATED BY SYZLANG-BRIDGE\n"
    types_gen += "use crate::grammar::resources;\n"
    types_gen += "use crate::grammar::types::*;\n\n"
    for type_id, type_obj in enumerate(syzlang['Types']):
        types_gen += gen_type_desc(syzlang, type_id, type_obj)

    type_table = "pub const TYPE_TABLE: &'static [Type] = &[\n" # ]
    for type_id, type_obj in enumerate(syzlang['Types']):
        type_enum = type_obj['Name'][:-4] # Strip 'Type' from the end
        type_table += f"\tType::{type_enum}(type_{type_id}),\n"
    type_table += "];\n"


    with open(proj_src_path+types_path, "w") as fp:
        fp.write(types_gen+type_table)

    syscalls_path = "grammar/syscalls/gen.rs"
    syscalls_gen = ""
    syscalls_gen += "use crate::grammar::syscalls::SyscallDef;\n"
    syscalls_gen += "use crate::grammar::syscalls::types;\n\n"
    syscalls_gen += "// THIS FILE IS AUTOGENERATED BY SYZLANG-BRIDGE\n"
    syscalls_gen += "pub const SYSCALL_TABLE: &'static [SyscallDef] = &[\n" #]
    for syscall in syzlang['Syscalls']:
        name = syscall['Name']
        #if not name.startswith('syz_') and name not in ['pause', 'exit', 'shutdown', 'rt_sigreturn', 'poll', 'execve', 'fork', 'clone', 'munmap']: # TODO
            #syscalls_gen += '\t' + gen_syscall_desc(syzlang, syscall)
        if name.startswith('syz_harness'):
            syscalls_gen += '\t' + gen_syscall_desc(syzlang, syscall)
    syscalls_gen += '];\n'

    with open(proj_src_path+syscalls_path, "w") as fp:
        fp.write(syscalls_gen)

if __name__ == "__main__":
    main()
