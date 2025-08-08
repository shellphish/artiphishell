from .utils import bool_as_go, escape_double_quotes, hex_escape
from typing import Optional
from enum import Enum

# Index into types array
class TypeIndex:
    def __init__(self, index: int):
        self.index = index

    def __repr__(self):
        return f"TypeIndex({self.index})"

    def as_rust_arg(self, type_name: str):
        return f"types::Type::{type_name[:-4]}(types::gen::type_{self.index})"

    def as_rust(self, type_name: str):
        return f"&Type::{type_name[:-4]}(type_{self.index})"

    def as_go(self):
        return f"Ref({self.index})"

class Direction(Enum):
    DirIn    = 0
    DirOut   = 1
    DirInOut = 2

direction_map = {
    0: Direction.DirIn,
    1: Direction.DirOut,
    2: Direction.DirInOut
}

direction_map_str = {
    Direction.DirIn.value:    "DirIn",
    Direction.DirOut.value:   "DirOut",
    Direction.DirInOut.value: "DirInOut",
}

class BinaryFormat(Enum):
    Native    = 0
    BigEndian = 1
    StrDec    = 2
    StrHex    = 3
    StrOct    = 4

binary_format_map = {
    0: BinaryFormat.Native,
    1: BinaryFormat.BigEndian,
    2: BinaryFormat.StrDec,
    3: BinaryFormat.StrHex,
    4: BinaryFormat.StrOct,
}

binary_format_map_str = {
    BinaryFormat.Native.value:    "FormatNative",
    BinaryFormat.BigEndian.value: "FormatBigEndian",
    BinaryFormat.StrDec.value:    "FormatStrDec",
    BinaryFormat.StrHex.value:    "FormatStrHex",
    BinaryFormat.StrOct.value:    "FormatStrOct",
}

class IntKind(Enum):
    IntPlain = 0
    IntRange = 1

int_kind_map = {
    0: IntKind.IntPlain,
    1: IntKind.IntRange
}

int_kind_map_str = {
    IntKind.IntPlain.value: "IntPlain",
    IntKind.IntRange.value: "IntRange"
}

class CsumKind(Enum):
    CsumInet   = 0
    CsumPseudo = 1

csum_kind_map = {
    0: CsumKind.CsumInet,
    1: CsumKind.CsumPseudo
}

csum_kind_map_str = {
    CsumKind.CsumInet.value:   "CsumInet",
    CsumKind.CsumPseudo.value: "CsumPseudo"
}

class ArrayKind(Enum):
    ArrayRandLen  = 0
    ArrayRangeLen = 1

array_kind_map = {
    0: ArrayKind.ArrayRandLen,
    1: ArrayKind.ArrayRangeLen
}

array_kind_map_str = {
    ArrayKind.ArrayRandLen.value:  "ArrayRandLen",
    ArrayKind.ArrayRangeLen.value: "ArrayRangeLen"
}

class BufferKind(Enum):
    BufferBlobRand   = 0
    BufferBlobRange  = 1
    BufferString     = 2
    BufferFilename   = 3
    BufferText       = 4
    BufferGlob       = 5
    BufferCompressed = 6

buffer_kind_map = {
    0: BufferKind.BufferBlobRand,
    1: BufferKind.BufferBlobRange,
    2: BufferKind.BufferString,
    3: BufferKind.BufferFilename,
    4: BufferKind.BufferText,
    5: BufferKind.BufferGlob,
    6: BufferKind.BufferCompressed,
}

buffer_kind_map_str = {
    BufferKind.BufferBlobRand.value:   "BufferBlobRand",
    BufferKind.BufferBlobRange.value:  "BufferBlobRange",
    BufferKind.BufferString.value:     "BufferString",
    BufferKind.BufferFilename.value:   "BufferFilename",
    BufferKind.BufferText.value:       "BufferText",
    BufferKind.BufferGlob.value:       "BufferGlob",
    BufferKind.BufferCompressed.value: "BufferCompressed"
}

class PseudoSyscallDep:
    def __init__(self, syscall, deps):
        self.name = syscall
        self.deps = deps

class Target:
    def __init__(self, target):
        self.build_os: str = target['BuildOS']
        self.syscall_numbers: bool = target['SyscallNumbers']
        self.int64_syscall_args: bool = target['Int64SyscallArgs']
        self.syscall_prefix: str = target['SyscallPrefix']
        self.executor_uses_shmem: bool = target['ExecutorUsesShmem']
        self.executor_uses_fork_server: bool = target['ExecutorUsesForkServer']
        self.host_fuzzer: bool = target['HostFuzzer']
        self.executor_bin: str = target['ExecutorBin']
        self.exe_extension: str = target['ExeExtension']
        self.kernel_object: str = target['KernelObject']
        self.cpp: str = target['CPP']
        self.pseudo_syscall_deps: list[PseudoSyscallDep] = list()
        for syscall, deps in target['PseudoSyscallDeps'].items():
            self.pseudo_syscall_deps += [PseudoSyscallDep(syscall, deps)]
        self.os: str = target['OS']
        self.arch: str = target['Arch']
        self.vm_arch: str = target['VMArch']
        self.ptr_size: int = target['PtrSize']
        self.page_size: int = target['PageSize']
        self.num_pages: int = target['NumPages']
        self.data_offset: int = target['DataOffset']
        self.int64_alignment: int = target['Int64Alignment']
        self.little_endian: bool = target['LittleEndian']
        self.cflags: list[str] = target['CFlags']
        self.triple: str = target['Triple']
        self.c_compiler: str = target['CCompiler']
        self.kernel_compiler: str = target['KernelCompiler']
        self.kernel_linker: str = target['KernelLinker']
        self.kernel_arch: str = target['KernelArch']
        self.broken_compiler: str = target['BrokenCompiler']
        self.host_endian: dict = target['HostEndian']

class Type:
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: int,
        is_varlen: int,

        id: Optional[TypeIndex] = None,
    ):
        self.id: Optional[TypeIndex] = id
        self.name: str = name
        self.size: int = size
        self.align: int = align
        self.is_optional: bool = is_optional
        self.is_varlen: bool = is_varlen

    @classmethod
    def from_json(cls, type_id, type_obj):
        id: TypeIndex = TypeIndex(type_id)
        name: str = type_obj['Value']['TypeName']
        size: int = type_obj['Value']['TypeSize']
        align: int = type_obj['Value']['TypeAlign']
        is_optional: bool = type_obj['Value']['IsOptional']
        is_varlen: bool = type_obj['Value']['IsVarlen']
        return cls(name, size, align, is_optional, is_varlen, id)

    def __repr__(self):
        return f"Type({self.id}: {self.name})"

    def as_rust(self, _ = None):
        return (
            f"\tname:\"{escape_double_quotes(self.name)}\",\n"
            f"\talign:{self.align},\n"
            f"\tsize:{self.size},\n"
            f"\tis_varlen:{bool_as_go(self.is_varlen)}"
            #f"\tis_optional:{bool_as_go(self.is_optional)}"
        )

    def as_go(self):
        return (
            f"TypeCommon:TypeCommon{{\n"
            f"\tTypeName:\"{escape_double_quotes(self.name)}\",\n"
            f"\tTypeAlign:{self.align},\n"
            f"\tTypeSize:{self.size},\n"
            f"\tIsOptional:{bool_as_go(self.is_optional)},\n"
            f"}}"
        )

class Field:
    def __init__(
        self,
        name: str,
        typ: TypeIndex | Type,
        has_dir: bool,
        direction: Direction
    ):
        if isinstance(typ, Type):
            if typ.id is None:
                raise Exception("Type must be registered via Types.add() before use")
            else:
                self.typ: TypeIndex = typ.id
        else:
            self.typ: TypeIndex = typ

        self.name: str = name
        self.has_dir: bool = has_dir
        self.direction: Direction = direction

    @staticmethod
    def from_json(field):
        name: str = field['Name']
        type_idx: TypeIndex = TypeIndex(field['Type'])
        has_dir: bool = field['HasDirection']
        direction: Direction = direction_map[field['Direction']]

        return Field(name, type_idx, has_dir, direction)

    def __repr__(self):
        return f"Field({self.name})"

    def as_rust(self, types: list[Type]):
        return (
            f"\tField {{\n"
            f"\t\tname: \"{self.name}\",\n"
            f"\t\ttyp: FieldType::Index({self.typ.index}),\n"
            f"\t\thas_dir: {bool_as_go(self.has_dir)},\n"
            f"\t\tdir: Dir::{direction_map_str[self.direction.value]},\n"
            f"\t}}"
        )
        return f"\t\t"

    def as_go(self):
        return f"{{Name:\"{self.name}\",Type:{self.typ.as_go()}}}"


class Syscall:
    def __init__(
        self,
        nr: int,
        name: str,
        call_name: str,
        ret: Optional[TypeIndex | Type],
        args: list[Field]
    ):
        self.ret: Optional[TypeIndex] = None
        if isinstance(ret, Type):
            if ret.id is None:
                raise Exception("Type must be registered via Types.add() before use")
            else:
                self.ret = ret.id
        elif isinstance(ret, TypeIndex):
            self.ret = ret

        self.nr: int = nr
        self.name: str = name
        self.call_name: str = call_name
        self.ret: Optional[TypeIndex] = ret
        self.args: list[TypeIndex] = args

    def __repr__(self):
        return f"Syscall({self.name})"

    @staticmethod
    def from_json(syscall):
        nr: int = syscall['NR']
        name: str = syscall['Name']
        call_name: str = syscall['CallName']
        ret: Optional[TypeIndex] = TypeIndex(syscall['Ret']) if not syscall['Ret'] is None else None

        args: list[Field] = list()
        if not syscall['Args'] is None:
            for arg in syscall['Args']:
                args += [Field.from_json(arg)]

        return Syscall(nr, name, call_name, ret, args)

    def as_go(self):
        ret = ""
        if not self.ret is None: ret = f",\nRet:{self.ret.as_go()}"
        args = '\n'.join([arg.as_go() + ',' for arg in self.args])
        return f"{{NR:{self.nr},Name:\"{self.name}\",CallName:\"{self.call_name}\",Args:[]Field{{\n{args}\n}}{ret}}}"

    def as_rust(self, types: list[Type]):
        args_str = ""
        for arg in self.args:
            args_str += f"\t(\"{arg.name}\", {arg.typ.as_rust_arg(types[arg.typ.index].type_name)}),\n"

        ret_str = f"Some(types::gen::type_{self.ret.index})" if self.ret is not None else "None"

        return (
            f"SyscallDef {{\n"
            f"    id: {self.nr},\n"
            f"    name: \"{self.name}\",\n"
            f"    args: &[\n"
            f"{args_str}"
            f"    ],\n"
            f"    ret: {ret_str},\n"
            f"}},"
        )

class Resource:
    def __init__(self, name: str, kind: list[str], values: list[int]):
        self.name: str = name
        self.kind: list[str] = kind
        self.values: list[int] = values

    def __repr__(self):
        return f"Resource({self.kind})"

    @staticmethod
    def from_json(resource_obj):
        name: str = resource_obj['Name']
        kind: list[str] = resource_obj['Kind']
        values: list[int] = resource_obj['Values']
        return Resource(name, kind, values)

    def as_rust(self, rsrc_idx: int):
        resource_kind = ", ".join(["rsrc_"+rsrc for rsrc in self.kind if rsrc != self.name])
        out = (
            f"pub const rsrc_{self.name}: ResourceDesc = ResourceDesc {{\n" # }}
            f"\tid: {rsrc_idx},\n"
            f"\tkind: &[{resource_kind}]\n"
            "};\n"
        )
        return out

    def as_go(self):
        kind = ", ".join(["\"" + k + "\"" for k in self.kind])
        values = ", ".join([str(v) for v in self.values])
        return f"{{Name:\"{self.name}\",Kind:[]string{{{kind}}},Values:[]uint64{{{values}}}}}"

class IntTypeGeneric(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: int,
        is_varlen: int,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        id: Optional[TypeIndex] = None,
    ):
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.format: BinaryFormat = format
        self.bitfield_len: int = bitfield_len
        self.bitfield_off: int = bitfield_off
        self.bitfield_unit: int = bitfield_unit
        self.bitfield_unit_off: int = bitfield_unit_off

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\targ_format: BinaryFormat::{binary_format_map_str[self.format.value]},\n"
            f"\tbitfield_len:{self.bitfield_len},\n"
            f"\tbitfield_off:{self.bitfield_off}"
            #f"\tbitfield_unit:{self.bitfield_unit}"
            #f"\tbitfield_unit_off:{self.bitfield_unit_off}\n"
        )

    def as_go(self):
        return (
            f"IntTypeCommon:IntTypeCommon{{\n"
            f"{super().as_go()},\n"
            f"\tArgFormat:{self.format.value},\n"
            f"\tBitfieldLen:{self.bitfield_len},\n"
            f"\tBitfieldOff:{self.bitfield_off},\n"
            f"\tBitfieldUnit:{self.bitfield_unit},\n"
            f"\tBitfieldUnitOff:{self.bitfield_unit_off},\n"
            f"}}"
        )

class IntType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        int_kind: IntKind,
        int_range: (int, int),

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "IntType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.int_kind: IntKind = int_kind
        self.int_range: (int, int) = int_range

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            int_kind_map[type_obj['Value']['Kind']],
            (type_obj['Value']['RangeBegin'], type_obj['Value']['RangeEnd']),

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        if self.int_kind.value == 0:
            kind = "IntKind::IntPlain"
        elif self.int_kind.value == 1:
            kind = f"IntKind::IntRange({self.int_range[0]}, {self.int_range[1]})"
        else:
            raise Exception("invalid int kind")

        return (
            f"{super().as_rust(types)},\n"
            f"\tkind: {kind}"
        )

    def as_go(self):
        return (
            f"&IntType{{\n"
            f"{super().as_go()},\n"
            f"\tKind:{self.int_kind.value},\n"
            f"\tRangeBegin:{self.int_range[0]},\n"
            f"\tRangeEnd:{self.int_range[1]},\n"
            f"}}"
        )

class ConstType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        val: int,
        is_pad: bool,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "ConstType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.val: int = val
        self.is_pad: bool = is_pad


    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            type_obj['Value']['Val'],
            type_obj['Value']['IsPad'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\tval:{self.val},\n"
            f"\tis_pad:{bool_as_go(self.is_pad)}\n"
        )

    def as_go(self):
        return (
            f"&ConstType{{\n"
            f"{super().as_go()},\n"
            f"\tVal:{self.val},\n"
            f"\tIsPad:{bool_as_go(self.is_pad)},\n"
            f"}}"
        )

class FlagsType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        vals: list[int],

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "FlagsType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.vals: list[int] = vals

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            type_obj['Value']['Vals'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        vals = ','.join([str(v) for v in self.vals])
        return (
            f"\t{super().as_rust(types)},\n"
            f"\tvals: &[{vals}]\n"
        )

    def as_go(self):
        vals = ','.join([str(v) for v in self.vals])
        return (
            f"&FlagsType{{\n"
            f"\t{super().as_go()},\n"
            f"\tVals:[]uint64{{{vals}}},\n"
            f"}}"
        )

class ResourceType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        desc: str,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "ResourceType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.format: BinaryFormat = format
        self.desc: str = desc

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['TypeName'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\targ_format: BinaryFormat::{binary_format_map_str[self.format.value]},\n"
            f"\tdesc: resources::gen::rsrc_{self.desc}"
        )

    def as_go(self):
        return (
            f"&ResourceType{{\n"
            f"{super().as_go()},\n"
            f"\tArgFormat:{self.format.value},\n"
            f"}}"
        )

class PtrType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        elem: TypeIndex | Type,
        direction: Direction,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "PtrType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        if isinstance(elem, Type):
            if elem.id is None:
                raise Exception("Type must be registered via Types.add() before use")
            else:
                self.elem: TypeIndex = elem.id
        else:
            self.elem: TypeIndex = elem
        self.direction: Direction = direction

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            TypeIndex(type_obj['Value']['Elem']),
            direction_map[type_obj['Value']['ElemDir']],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\telem:{self.elem.as_rust(types[self.elem.index].type_name)},\n"
            f"\tdir: Dir::{direction_map_str[self.direction.value]},\n"
        )

    def as_go(self):
        return (
            f"&PtrType{{\n"
            f"{super().as_go()},\n"
            f"\tElem:{self.elem.as_go()},\n"
            f"\tElemDir:{self.direction.value},\n"
            f"}}"
        )

class LenType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        bitsize: int,
        offset: bool,
        path: list[str],

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "LenType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.bitsize: int = bitsize
        self.offset: bool = offset
        self.path: list[str] = path

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            type_obj['Value']['BitSize'],
            type_obj['Value']['Offset'],
            type_obj['Value']['Path'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        path = ",\n".join(["\"" + p + "\"" for p in self.path])
        return (
            f"{super().as_rust(types)},\n"
            f"bit_size:{self.bitsize},\n"
            f"offset:{bool_as_go(self.offset)},\n"
            f"path: &[{path}]\n"
        )

    def as_go(self):
        path = ",\n".join(["\"" + p + "\"" for p in self.path])
        return (
            f"&LenType{{\n"
            f"{super().as_go()},\n"
            f"BitSize:{self.bitsize},\n"
            f"Path:[]string{{{path}}},\n"
            f"}}"
        )

class BufferType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        kind: BufferKind,
        values: list[str],
        noz: bool,
        range_begin: int,
        range_end: int,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "BufferType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.kind: BufferKind = kind
        self.values: list[str] = values
        self.noz: bool = noz
        self.range_begin: int = range_begin
        self.range_end: int = range_end

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            buffer_kind_map[type_obj['Value']['Kind']],
            type_obj['Value']['Values'],
            type_obj['Value']['NoZ'],
            type_obj['Value']['RangeBegin'],
            type_obj['Value']['RangeEnd'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        values = ""
        if not self.values is None:
            values = ", ".join(f"\"{hex_escape(v)}\"" for v in self.values)
        return (
            f"{super().as_rust(types)},\n"
            f"\tkind:BufferKind::{buffer_kind_map_str[self.kind.value]},\n"
            f"\tvalues: &[{values}],\n"
            f"\tnoz:{bool_as_go(self.noz)},\n"
            f"\trange_begin:{self.range_begin},\n"
            f"\trange_end:{self.range_end}\n"
        )

    def as_go(self):
        values = ""
        if not self.values is None:
            values = ", ".join(f"\"{hex_escape(v)}\"" for v in self.values)
        return (
            f"&BufferType{{\n"
            f"{super().as_go()},\n"
            f"\tKind:{self.kind.value},\n"
            f"\tValues:[]string{{{values}}},\n"
            f"\tNoZ:{bool_as_go(self.noz)},\n"
            f"\tRangeBegin:{self.range_begin},\n"
            f"\tRangeEnd:{self.range_end},\n"
            f"}}"
        )

class ArrayType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        kind: ArrayKind,
        array_range: (int, int),
        elem: TypeIndex | Type,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "ArrayType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.kind: ArrayKind = kind
        self.array_range: (int, int) = array_range
        if isinstance(elem, Type):
            if elem.id is None:
                raise Exception("Type must be registered via Types.add() before use")
            else:
                self.elem: TypeIndex = elem.id
        else:
            self.elem: TypeIndex = elem

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            array_kind_map[type_obj['Value']['Kind']],
            (type_obj['Value']['RangeBegin'], type_obj['Value']['RangeEnd']),
            TypeIndex(type_obj['Value']['Elem']),

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
         if self.kind.value == 0:
             kind = "ArrayKind::ArrayRandLen"
         elif self.kind.value == 1:
             kind = f"ArrayKind::ArrayRangeLen({self.array_range[0]}, {self.array_range[1]})"
         else:
             raise Exception("invalid array kind")

         return (
             f"{super().as_rust(types)},\n"
             f"\tkind:{kind},\n"
             f"\telem:{self.elem.as_rust(types[self.elem.index].type_name)}\n"
         )

    def as_go(self):
         return (
             f"&ArrayType{{\n"
             f"{super().as_go()},\n"
             f"Kind:{self.kind.value},\n"
             f"RangeBegin:{self.array_range[0]},\n"
             f"RangeEnd:{self.array_range[1]},\n"
             f"Elem:{self.elem.as_go()},\n"
             f"}}"
         )

class StructType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        fields: list[Field],

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "StructType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.fields = fields

    @classmethod
    def from_json(cls, type_id, type_obj):
        fields = list()
        for field in type_obj['Value']['Fields']:
            fields += [Field.from_json(field)]
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            fields,

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        fields = ",\n".join([f.as_rust(types) for f in self.fields])
        return (
            f"{super().as_rust(types)},\n"
            f"\tfields: &[\n{fields}\n\t],\n"
        )

    def as_go(self):
        fields = ",\n".join([f.as_go() for f in self.fields])
        if len(fields) > 0:
            fields += ',\n'
        return (
            f"&StructType{{\n"
            f"{super().as_go()},\n"
            f"\tFields:[]Field{{\n{fields}}},\n"
            f"}}"
        )

class UnionType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        fields: list[Field],

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "UnionType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.fields = fields

    @classmethod
    def from_json(cls, type_id, type_obj):
        fields = list()
        for field in type_obj['Value']['Fields']:
            fields += [Field.from_json(field)]
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            fields,

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        fields = ",\n".join([f.as_rust(types) for f in self.fields])
        if len(fields) > 0:
            fields += ',\n'
        return (
            f"{super().as_rust(types)},\n"
            f"\tfields: &[\n{fields}\n\t],\n"
        )

    def as_go(self):
        fields = ",\n".join([f.as_go() for f in self.fields])
        return (
            f"&UnionType{{\n"
            f"{super().as_go()},\n"
            f"\tFields:[]Field{{\n{fields}}},\n"
            f"}}"
        )

class VmaType(Type):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        vma_range: (int, int),

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "VmaType"
        super().__init__(name, size, align, is_optional, is_varlen, id=id)
        self.vma_range: (int, int) = vma_range

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            (type_obj['Value']['RangeBegin'], type_obj['Value']['RangeEnd']),

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\trange_begin:{self.vma_range[0]},\n"
            f"\trange_end:{self.vma_range[1]}\n"
        )

    def as_go(self):
        return (
            f"&VmaType{{\n"
            f"{super().as_go()},\n"
            f"\tRangeBegin:{self.vma_range[0]},\n"
            f"\tRangeEnd:{self.vma_range[1]},\n"
            f"}}"
        )

class ProcType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        values_start: int,
        values_per_proc: int,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "ProcType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.values_start = values_start
        self.values_per_proc = values_per_proc

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            type_obj['Value']['ValuesStart'],
            type_obj['Value']['ValuesPerProc'],

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\tvalues_start:{self.values_start},\n"
            f"\tvalues_per_proc:{self.values_per_proc}\n"
        )

    def as_go(self):
        return (
            f"&ProcType{{\n"
            f"{super().as_go()},\n"
            f"\tValuesStart:{self.values_start},\n"
            f"\tValuesPerProc:{self.values_per_proc},\n"
            f"}}"
        )

class CsumType(IntTypeGeneric):
    def __init__(
        self,
        name: str,
        size: int,
        align: int,
        is_optional: bool,
        is_varlen: bool,

        format: BinaryFormat,
        bitfield_len: int,
        bitfield_off: int,
        bitfield_unit: int,
        bitfield_unit_off: int,

        kind: CsumKind,
        buf: str,
        protocol: int,

        id: Optional[TypeIndex] = None,
    ):
        self.type_name = "CsumType"
        super().__init__(name, size, align, is_optional, is_varlen, format, bitfield_len, bitfield_off, bitfield_unit, bitfield_unit_off, id=id)
        self.kind: CsumKind = kind
        self.buf: str = buf
        self.protocol: int = protocol

    @classmethod
    def from_json(cls, type_id, type_obj):
        return cls(
            type_obj['Value']['TypeName'],
            type_obj['Value']['TypeSize'],
            type_obj['Value']['TypeAlign'],
            type_obj['Value']['IsOptional'],
            type_obj['Value']['IsVarlen'],

            binary_format_map[type_obj['Value']['ArgFormat']],
            type_obj['Value']['BitfieldLen'],
            type_obj['Value']['BitfieldOff'],
            type_obj['Value']['BitfieldUnit'],
            type_obj['Value']['BitfieldUnitOff'],

            csum_kind_map[type_obj['Value']['Kind']],
            type_obj['Value']['Buf'],
            type_obj['Value']['Protocol'], # for CsumPseudo

            TypeIndex(type_id),
        )

    def as_rust(self, types: list[Type]):
        return (
            f"{super().as_rust(types)},\n"
            f"\tbuf:\"{escape_double_quotes(self.buf)}\",\n"
            f"\tprotocol:{self.protocol}\n"
        )

    def as_go(self):
        return (
            f"&CsumType{{\n"
            f"{super().as_go()},\n"
            f"\tBuf:\"{escape_double_quotes(self.buf)}\",\n"
            f"\tProtocol:{self.protocol},\n"
            f"}}"
        )

def construct_type(syzlang, type_id):
    type_obj = syzlang['Types'][type_id]
    match type_obj['Name']:
        case "IntType":      return IntType.from_json(type_id, type_obj)
        case "ConstType":    return ConstType.from_json(type_id, type_obj)
        case "FlagsType":    return FlagsType.from_json(type_id, type_obj)
        case "ResourceType": return ResourceType.from_json(type_id, type_obj)
        case "PtrType":      return PtrType.from_json(type_id, type_obj)
        case "LenType":      return LenType.from_json(type_id, type_obj)
        case "BufferType":   return BufferType.from_json(type_id, type_obj)
        case "ArrayType":    return ArrayType.from_json(type_id, type_obj)
        case "StructType":   return StructType.from_json(type_id, type_obj)
        case "UnionType":    return UnionType.from_json(type_id, type_obj)
        case "VmaType":      return VmaType.from_json(type_id, type_obj)
        case "ProcType":     return ProcType.from_json(type_id, type_obj)
        case "CsumType":     return CsumType.from_json(type_id, type_obj)
    raise Exception("wtf not a real syzlang type:", type_obj)

class Const:
    def __init__(self, name: str, value: int):
        self.name: str = name
        self.value: int = value

    def as_go(self):
        return f"{{Name:\"{self.name}\",Value:{self.value}}}"

class Flag:
    def __init__(self, name: str, values: list[int]):
        self.name: str = name
        self.values: list[str] = values

    def as_go(self):
        values = ", ".join(["\"" + v + "\"" for v in self.values]  )
        return f"{{\"{self.name}\",[]string{{{values}}}}}"
