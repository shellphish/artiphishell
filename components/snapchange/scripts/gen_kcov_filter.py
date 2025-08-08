import click
from subprocess import check_output


def gen_symbol_map(vmlinux):
    output = check_output(["nm", "-S", vmlinux]).decode().splitlines()
    symbol_map = {}
    for line in output:
        try:
            addr, size, _, name = line.strip().split(" ")
            symbol_map[name] = (int(addr, 16), int(size, 16))
        except:
            continue
    
    return symbol_map

def find_all_pc(vmlinux, func_ranges):
    output = check_output([f"objdump -d {vmlinux} | grep 'call.*__sanitizer_cov_trace_pc'"], shell=True).decode().splitlines()
    ret = []
    for line in output:
        addr = int(line.split(":")[0], 16)
        for start, end in func_ranges:
            if addr >= start and addr < end:
                ret.append(addr+5)
                break
    return ret


@click.command()
@click.argument('vmlinux', type=click.Path(exists=True))
@click.argument('functions', type=click.File('r'))
@click.argument('kcov_filter', type=click.File('w'))
def gen_kcov_filter(vmlinux, functions, kcov_filter):
    data = []
    symbol_map = gen_symbol_map(vmlinux)
    for func_name in functions.readlines():
        try:
            start, end = symbol_map[func_name.strip()]
            data.append((start, start+end))
        except:
            continue
    pc_locations = find_all_pc(vmlinux, data)
    with kcov_filter.open() as f:
        f.write('\n'.join(f"{hex(x)}" for x in pc_locations))


if __name__ == '__main__':
    gen_kcov_filter()