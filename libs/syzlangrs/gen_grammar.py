from syzlang_bridge import *
import sys

def main(argc, argv):
    if argc < 2:
        print("Usage: gen_grammar.py <TARGET>")
        exit(1)

    target = argv[1]

    if target not in ['snapchange', 'lark']:
        print(f"Invalid target {target}! Target must be one of [\"snapchange\", \"lark\"]")

    syzlang = Syzlang.from_json('./syzkaller/sys/json/linux/amd64.json')

    match target:
        case "snapchange":
            # this is pretty hackish..
            syz_harness = syzlang.syscalls['syz_harness']
            syzlang.syscalls._syscalls = [syz_harness]
        case "lark":
            blacklist = [
                'pause',
                'exit',
                'exit_group',
                'shutdown',
                'rt_sigreturn',
                'poll',
                'execve',
                'fork',
                'clone',
                'munmap',
                'nanosleep'
            ]

            keep = []
            for syscall in syzlang.syscalls:
                if syscall.name.startswith('syz_'): continue
                if syscall.name in blacklist: continue
                keep += [syscall]

            syzlang.syscalls._syscalls = keep

    syzlang.generate_rust("./src")

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
