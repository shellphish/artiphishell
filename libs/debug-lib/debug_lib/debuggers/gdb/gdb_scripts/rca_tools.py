# rca_tools.py  – “Root-Cause Analysis” helpers for GDB
import gdb, re, os, tempfile, pickle, difflib
#######################################################################
# Utility helpers
#######################################################################
def to_addr(expr):
    """Return an int address for a user expression (symbol, $reg, 0x…)."""
    return int(gdb.parse_and_eval(expr))

def current_pc():
    return int(gdb.parse_and_eval("$pc"))

def highlight(s):
    return f"\033[1;32m{s}\033[0m"

def err(s):
    gdb.write(f"\033[1;31m{s}\033[0m\n", gdb.STDERR)

#######################################################################
# 1. find-last-write
#######################################################################
class FindLastWrite(gdb.Command):
    """find-last-write <expr> – reverse-exec until expr is written."""
    def __init__(self): super().__init__("find-last-write", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        if not gdb.parameter("record") and not gdb.parameter("record") :
            err("You must be running in a recorded execution (record/target replay).")
            return
        expr = arg.strip()
        addr = to_addr(expr)
        cond = f"*({addr:#x}) != $__old"  # stop when byte differs
        gdb.execute(f"set $__old = *({addr:#x})")
        gdb.execute(f"while {cond}\n  reverse-stepi\nend")
        gdb.execute("bt")

FindLastWrite()

#######################################################################
# 2. watch-var
#######################################################################
class WatchVar(gdb.Command):
    """watch-var <expr> [N] – record next N changes of expr."""
    def __init__(self): super().__init__("watch-var", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        parts = arg.split()
        if not parts: return
        expr, limit = parts[0], int(parts[1]) if len(parts) > 1 else 10
        gdb.execute(f"printf \"Watching {expr} for {limit} changes…\\n\"")
        gdb.execute(f"set $__watch_old = {expr}")
        gdb.execute(f"set $__watch_cnt = 0")
        gdb.execute(f"while $__watch_cnt < {limit}\n"
                    f"  continue\n"
                    f"  if {expr} != $__watch_old\n"
                    f"     printf \"{highlight('Changed')} at $pc=%p : {expr}=%s\\n\", $pc, {expr}\n"
                    f"     set $__watch_old = {expr}\n"
                    f"     set $__watch_cnt = $__watch_cnt + 1\n"
                    f"  end\n"
                    f"end")

WatchVar()

#######################################################################
# 3. heap-history  (ptmalloc/glibc only)
#######################################################################
class HeapHistory(gdb.Command):
    """heap-history <ptr> – show malloc/free sites for ptr."""
    def __init__(self): super().__init__("heap-history", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        ptr = to_addr(arg.strip())
        try:
            gdb.execute(f"heap find {ptr:#x}")
        except gdb.error:
            err("Install GDB heap extension (`gef`, `pwndbg`, or glibc-gdb.py`).")

HeapHistory()

#######################################################################
# 4. value-prop  (very light taint via ’reverse-finestep')
#######################################################################
class ValueProp(gdb.Command):
    """value-prop <expr> [depth] [fwd|back] – show propagation chain."""
    def __init__(self): super().__init__("value-prop", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        parts = arg.split()
        if len(parts) < 1: return
        expr = parts[0]
        depth = int(parts[1]) if len(parts) > 1 else 4
        dirn = parts[2] if len(parts) > 2 else "back"
        if dirn not in ("back", "fwd"): err("dir must be back/fwd"); return
        step = "reverse-stepi" if dirn == "back" else "stepi"
        chain = []
        gdb.execute(f"printf \"Tracing {expr} ({dirn})…\\n\"")
        for _ in range(depth):
            gdb.execute(step)
            loc = gdb.parse_and_eval("$pc")
            chain.append(hex(int(loc)))
        gdb.write(" → ".join(chain)+"\n")

ValueProp()

#######################################################################
# 5. call-graph
#######################################################################
class CallGraph(gdb.Command):
    """call-graph <func> [depth] – show callers (static/dynamic blend)."""
    def __init__(self): super().__init__("call-graph", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        parts = arg.split()
        if not parts: return
        func = parts[0]; depth = int(parts[1]) if len(parts) > 1 else 5
        seen=set()
        def recurse(f, d):
            if d>depth or f in seen: return
            seen.add(f)
            gdb.write("  "*d + f + "\n")
            out = gdb.execute(f"grep -n \"{f}(\" **/*.c", to_string=True)
            for m in re.finditer(r"([A-Za-z0-9_]+)\(", out):
                recurse(m.group(1), d+1)
        recurse(func,0)

CallGraph()

#######################################################################
# 6. bt-full  – alias
#######################################################################
class BtFull(gdb.Command):
    """bt-full – full backtrace with locals."""
    def __init__(self): super().__init__("bt-full", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty): gdb.execute("info locals; bt full")
BtFull()

#######################################################################
# 7. disasm±
#######################################################################
class DisasPM(gdb.Command):
    """disasm± <addr|func> [N] – source+asm around point."""
    def __init__(self): super().__init__("disasm±", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        parts=arg.split(); target=parts[0] if parts else "$pc"
        N = int(parts[1]) if len(parts)>1 else 6
        gdb.execute(f"disassemble /m {target}, +{N}")
        gdb.execute(f"disassemble /m {target}, -{N}")
DisasPM()

#######################################################################
# 8. src-search
#######################################################################
class SrcSearch(gdb.Command):
    """src-search /regex/ [glob] – grep sources loaded in symtab."""
    def __init__(self): super().__init__("src-search", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        m=re.match(r'\s*/(.+)/\s*(.*)', arg)
        if not m: err("syntax: src-search /regex/ [glob]"); return
        regex, globpat=m.group(1), m.group(2) or "*.[ch]"
        import glob, pathlib
        rx=re.compile(regex)
        for path in glob.glob(globpat, recursive=True):
            for i,l in enumerate(open(path,errors="ignore")):
                if rx.search(l): gdb.write(f"{path}:{i+1}:{l}")

SrcSearch()

#######################################################################
# 9. ctx-diff + 10. checkpoint/restore
#######################################################################
_CTX_DIR=tempfile.mkdtemp(prefix="gdbctx_")
def save_ctx(name):
    fname=os.path.join(_CTX_DIR,f"{name}.ctx")
    regs={r: int(gdb.parse_and_eval(f"${r}")) for r in
          ["pc","sp","bp","ax","bx","cx","dx","si","di"]}
    mem=gdb.selected_frame().read_memory(to_addr("$sp"), 256)
    pickle.dump((regs,bytes(mem)), open(fname,"wb"))
    return fname

class Checkpoint(gdb.Command):
    """checkpoint – snapshot regs+SP chunk, returns id."""
    def __init__(self): super().__init__("checkpoint", gdb.COMMAND_USER)
    def invoke(self, arg, t):
        tag=arg.strip() or f"cp{len(os.listdir(_CTX_DIR))}"
        f=save_ctx(tag); gdb.write(f"Saved ↦ {tag}\n")
Checkpoint()

class Restore(gdb.Command):
    """restore <id> – restore snapshot."""
    def __init__(self): super().__init__("restore", gdb.COMMAND_USER)
    def invoke(self, arg, t):
        tag=arg.strip(); fname=os.path.join(_CTX_DIR,f"{tag}.ctx")
        regs,mem=pickle.load(open(fname,"rb"))
        for r,v in regs.items(): gdb.execute(f"set ${r} = {v}")
        gdb.selected_inferior().write_memory(regs["sp"], mem)
        gdb.write(f"Restored {tag}\n")
Restore()

class CtxDiff(gdb.Command):
    """ctx-diff <id1> <id2> [what] – diff regs/locals/mem."""
    def __init__(self): super().__init__("ctx-diff", gdb.COMMAND_USER)
    def invoke(self,arg,t):
        p=arg.split(); a,b=p[:2]; what=p[2:] or ["regs"]
        da,db=[pickle.load(open(os.path.join(_CTX_DIR,f"{x}.ctx"),"rb")) for x in (a,b)]
        if "regs" in what:
            ra,rb=da[0],db[0]
            for k in ra:
                if ra[k]!=rb[k]:
                    gdb.write(f"{k}: {ra[k]:#x} → {rb[k]:#x}\n")
        if "mem" in what:
            for diff in difflib.unified_diff(map(hex,da[1]),map(hex,db[1])):
                gdb.write(diff+"\n")
CtxDiff()