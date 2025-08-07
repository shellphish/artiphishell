import idc
import idautils
import ida_bytes
import idaapi

def find_segment_by_name(name):
    for s in idautils.Segments():
        if idc.get_segm_name(s) == name:
            return {
                'start': idc.get_segm_start(s),
                'end': idc.get_segm_end(s),
                'name': name,
            }
    return None

guards = find_segment_by_name('__sancov_guards')

addr_init_offset = idc.get_name_ea_simple('__sanitizer_cov_trace_pc_guard_init.offset')
init_offset = idaapi.get_dword(addr_init_offset)


for guard_addr in range(guards['start'], guards['end'], 4):
    guard_idx = (guard_addr - guards['start']) // 4
    guard_value = init_offset + 1 + guard_idx
    idaapi.set_name(guard_addr, f'__sancov_guards_0x{guard_value:x}')
