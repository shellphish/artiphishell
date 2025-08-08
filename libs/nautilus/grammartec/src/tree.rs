//grammartec/src/tree.rs/ Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo
#![allow(deprecated)]

use nix::unistd::{fork, ForkResult, pipe};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::resource::{setrlimit, Resource};
use std::os::unix::io::FromRawFd;
use std::io::Read;
use pyo3::exceptions::PyValueError;

use std::cmp;
use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::marker::Sized;
use std::ffi::c_int;
use std::ffi::c_void;
use std::time::Instant;

use context::Context;
use newtypes::{NTermID, NodeID, RuleID};

use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use pyo3::types::{PyBytes, PyTuple, PyDict};

use recursion_info::RecursionInfo;
use rule::{PlainRule, Rule, RuleChild, RuleIDOrCustom, ScriptRule, RegExpRule, IntRule, BytesRule, LiteralRule};
use rand::thread_rng;
use rand::Rng;

// Liberal maximum amount each python allocator can use, its possible things
// like library imports could have a large memory footprint that wont end up in
// the final output
const MEMORY_ALLOCATOR_MAX: usize = 100 << 20;

// https://github.com/PyO3/pyo3/issues/4008
#[derive(Debug)]
enum Event {
    Call,
    Exception,
    Line,
    Return,
    CCall,
    CException,
    CReturn,
    Opcode,
}

impl Event {
    fn from_c(what: c_int) -> Self {
         match what {
             pyo3_ffi::PyTrace_CALL => Self::Call,
             pyo3_ffi::PyTrace_EXCEPTION => Self::Exception,
             pyo3_ffi::PyTrace_LINE => Self::Line,
             pyo3_ffi::PyTrace_RETURN => Self::Return,
             pyo3_ffi::PyTrace_C_CALL => Self::CCall,
             pyo3_ffi::PyTrace_C_EXCEPTION => Self::CException,
             pyo3_ffi::PyTrace_C_RETURN => Self::CReturn,
             pyo3_ffi::PyTrace_OPCODE => Self::Opcode,
             _ => unreachable!("invalid pytrace event")
         }
    }
}

#[pyclass]
struct Profiler {
    enabled: bool,
    hit_ct: u64,
    start_time: Instant,
}

impl Profiler {
    fn profile(
        &mut self,
        _frame: PyObject,
        _arg: Option<PyObject>,
        event: Event,
        _py: Python,
    ) -> PyResult<()> {
        if self.enabled && matches!(event, Event::CCall | Event::Call) && self.hit_ct >= 1000 {
            self.hit_ct = 0;

            if self.start_time.elapsed().as_millis() > 500 {
                println!("Python profiler timeout handler was hit!");
                return Err(PyException::new_err("took too long :("));
            }
        }
        self.hit_ct += 1;
        Ok(())
    }
}

pub extern "C" fn profile_callback(
    _obj: *mut ffi::PyObject,
    _frame: *mut ffi::PyFrameObject,
    what: c_int,
    _arg: *mut ffi::PyObject,
) -> c_int {
    let event = Event::from_c(what);
    // An optimisation for my use case that might not be worth trying to allow upstream
    // match event {
    //     Event::Call => (),
    //     Event::Return => (),
    //     _ => return 0;
    //}
    let _frame = _frame as *mut ffi::PyObject;
    Python::with_gil(|py| {
        // Safety:
        //
        // `from_borrowed_ptr_or_err` must be called in an unsafe block.
        //
        // `_obj` is a reference to our `Profiler` wrapped up in a Python object, so
        // we can safely convert it from an `ffi::PyObject` to a `PyObject`.
        //
        // We borrow the object so we don't break reference counting.
        //
        // https://docs.rs/pyo3/latest/pyo3/struct.Py.html#method.from_borrowed_ptr_or_err
        // https://docs.python.org/3/c-api/init.html#c.Py_tracefunc
        let obj = match unsafe { PyObject::from_borrowed_ptr_or_err(py, _obj) } {
            Ok(obj) => obj,
            Err(err) => {
                err.restore(py);
                return -1;
            }
        };
        let mut profiler = match obj.extract::<PyRefMut<Profiler>>(py) {
            Ok(profiler) => profiler,
            Err(err) => {
                err.restore(py);
                return -1;
            }
        };

        // Safety:
        //
        // `from_borrowed_ptr_or_err` must be called in an unsafe block.
        //
        // `_frame` is an `ffi::PyFrameObject` which can be converted safely
        // to a `PyObject`. We can later convert it into a `pyo3::types::PyFrame`.
        //
        // We borrow the object so we don't break reference counting.
        //
        // https://docs.rs/pyo3/latest/pyo3/struct.Py.html#method.from_borrowed_ptr_or_err
        // https://docs.python.org/3/c-api/init.html#c.Py_tracefunc
        let frame = match unsafe { PyObject::from_borrowed_ptr_or_err(py, _frame) } {
            Ok(frame) => frame,
            Err(err) => {
                err.restore(py);
                return -1;
            }
        };

        // Safety:
        //
        // `from_borrowed_ptr_or_opt` must be called in an unsafe block.
        //
        // `_arg` is either a `Py_None` (PyTrace_CALL) or any PyObject (PyTrace_RETURN) or
        // NULL (PyTrace_RETURN).
        //
        // We borrow the object so we don't break reference counting.
        //
        // https://docs.rs/pyo3/latest/pyo3/struct.Py.html#method.from_borrowed_ptr_or_opt
        // https://docs.python.org/3/c-api/init.html#c.Py_tracefunc
        let arg = unsafe { PyObject::from_borrowed_ptr_or_opt(py, _arg) };
        // `_arg` is `NULL` when the frame exits with an exception unwinding instead of a normal return.
        // So it might be possible to make `arg` a `PyResult` here instead of an option, but I haven't worked out the detail of how that would work.

        match profiler.profile(frame, arg, event, py) {
            Ok(_) => 0,
            Err(err) => {
                err.restore(py);
                return -1;
            }
        }
    })

}

#[pyfunction]
fn register_profiler() -> PyResult<()> {
    Python::with_gil(|py| {
        let prof: Py<Profiler> = Py::new(py, Profiler { enabled: true, hit_ct: 0, start_time: Instant::now() }).unwrap();
        unsafe {
            ffi::PyEval_SetProfile(Some(profile_callback), prof.into_ptr());
        }
    });
    Ok(())
}

#[pyfunction]
fn unregister_profiler() -> PyResult<()> {
    Python::with_gil(|py| {
        unsafe {
            ffi::PyEval_SetProfile(None, std::ptr::null_mut());
        }
    });
    Ok(())
}

#[derive(Debug)]
struct AllocatorEx {
    malloc: Option<extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    calloc: Option<extern "C" fn(*mut c_void, usize, usize) -> *mut c_void>,
    realloc: Option<extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void>,
    free: Option<extern "C" fn(*mut c_void, *mut c_void)>,
}

//#[derive(Debug)]
struct AllocatorCtx {
    original: AllocatorEx,
    memory_allocated: usize,
    enabled: bool,
}

impl AllocatorCtx {
    pub fn new(domain: ffi::PyMemAllocatorDomain) -> Self {
        let allocator_raw = get_allocator(domain);
        let original = AllocatorEx {
            malloc: allocator_raw.malloc,
            calloc: allocator_raw.calloc,
            realloc: allocator_raw.realloc,
            free: allocator_raw.free,
        };
        AllocatorCtx {
            original,
            memory_allocated: 0,
            enabled: true,
        }
    }
}


#[no_mangle]
pub extern "C" fn malloc_hook(ctx: *mut c_void, size: usize) -> *mut c_void {
    unsafe {
        let allocator_ctx = &mut *(ctx as *mut AllocatorCtx);
        if allocator_ctx.enabled && allocator_ctx.memory_allocated + size > MEMORY_ALLOCATOR_MAX {
            allocator_ctx.enabled = false;
            return std::ptr::null_mut()
        }
        allocator_ctx.memory_allocated += size;
        (allocator_ctx.original.malloc.unwrap())(ctx, size)
    }
}

#[no_mangle]
pub extern "C" fn calloc_hook(ctx: *mut c_void, size: usize, items: usize) -> *mut c_void {
    unsafe {
        let allocator_ctx = &mut *(ctx as *mut AllocatorCtx);
        if allocator_ctx.enabled && allocator_ctx.memory_allocated + (size * items) > MEMORY_ALLOCATOR_MAX {
            allocator_ctx.enabled = false;
            return std::ptr::null_mut()
        }
        allocator_ctx.memory_allocated += size * items;
        (allocator_ctx.original.calloc.unwrap())(ctx, size, items)
    }
}

#[no_mangle]
pub extern "C" fn realloc_hook(ctx: *mut c_void, curr: *mut c_void, size: usize) -> *mut c_void {
    unsafe {
        let allocator_ctx = &mut *(ctx as *mut AllocatorCtx);
        if allocator_ctx.enabled && allocator_ctx.memory_allocated + size > MEMORY_ALLOCATOR_MAX {
            allocator_ctx.enabled = false;
            return std::ptr::null_mut()
        }
        allocator_ctx.memory_allocated += size;
        (allocator_ctx.original.realloc.unwrap())(ctx, curr, size)
    }
}

#[no_mangle]
pub extern "C" fn free_hook(ctx: *mut c_void, ptr: *mut c_void) {
    unsafe {
        let allocator_ctx = &mut *(ctx as *mut AllocatorCtx);
        // unfortunately we don't know the amount freed :(
        (allocator_ctx.original.free.unwrap())(ctx, ptr)
    }
}

fn get_allocator(domain: ffi::PyMemAllocatorDomain) -> ffi::PyMemAllocatorEx {
    Python::with_gil(|py| {
        unsafe {
            let mut allocator = ffi::PyMemAllocatorEx {
                ctx: std::ptr::null_mut(),
                calloc: None,
                malloc: None,
                free: None,
                realloc: None,
            };
            ffi::PyMem_GetAllocator(domain, &mut allocator);
            allocator
        }
    })
}

fn register_allocator_hooks(domain: ffi::PyMemAllocatorDomain, ctx: *mut c_void) {
    Python::with_gil(|py| {
        unsafe {
            let mut allocator = ffi::PyMemAllocatorEx {
                ctx,
                calloc: Some(calloc_hook),
                malloc: Some(malloc_hook),
                free: Some(free_hook),
                realloc: Some(realloc_hook),
            };
            ffi::PyMem_SetAllocator(domain, &mut allocator);
        }
    })
}

fn unregister_allocator_hooks(domain: ffi::PyMemAllocatorDomain, ctx: &AllocatorCtx) {
    Python::with_gil(|py| {
        unsafe {
            let mut allocator = ffi::PyMemAllocatorEx {
                ctx: std::ptr::null_mut(),
                calloc: ctx.original.calloc,
                malloc: ctx.original.malloc,
                free: ctx.original.free,
                realloc: ctx.original.realloc,
            };
            ffi::PyMem_SetAllocator(domain, &mut allocator);
        }
    })
}

enum UnparseStep<'dat> {
    Term(&'dat [u8]),
    Int(&'dat [u8]),
    Bytes(&'dat [u8]),
    Nonterm(NTermID),
    Script(usize, PyObject),
    PushBuffer(),
}

struct Unparser<'data, 'tree: 'data, 'ctx: 'data, W: Write, T: TreeLike> {
    tree: &'tree T,
    stack: Vec<UnparseStep<'data>>,
    buffers: Vec<std::io::Cursor<Vec<u8>>>,
    w: W,
    i: usize,
    ctx: &'ctx Context,
}

impl<'data, 'tree: 'data, 'ctx: 'data, W: Write, T: TreeLike> Unparser<'data, 'tree, 'ctx, W, T> {
    fn new(nid: NodeID, w: W, tree: &'tree T, ctx: &'ctx Context) -> Self {
        let i = nid.to_i();
        let nt = tree.get_rule(NodeID::from(i), ctx).nonterm();
        let op = UnparseStep::<'data>::Nonterm(nt);
        let stack = vec![op];
        return Self {
            stack,
            buffers: vec![],
            w,
            tree,
            i,
            ctx,
        };
    }

    fn unparse_step(&mut self) -> bool {
        match self.stack.pop() {
            Some(UnparseStep::Term(data)) => self.write(data),
            Some(UnparseStep::Int(data)) => self.pack(data),
            Some(UnparseStep::Bytes(data)) => self.pack(data),
            Some(UnparseStep::Nonterm(nt)) => self.nonterm(nt),
            Some(UnparseStep::Script(num, expr)) => self.unwrap_script(num, expr),
            Some(UnparseStep::PushBuffer()) => self.push_buffer(),
            None => return false,
        };
        return true;
    }

    fn pack(&mut self, data: &[u8]) {
        self.write(&data);
    }

    fn write(&mut self, data: &[u8]) {
        if let Some(buff) = self.buffers.last_mut() {
            buff.write(data).unwrap();
        } else {
            self.w.write(data).unwrap();
        }
    }

    fn nonterm(&mut self, nt: NTermID) {
        self.next_rule(nt);
    }

    fn unwrap_script(&mut self, num: usize, expr: PyObject) {
        Python::with_gil(|py| {
            if let Err(e) = self.script(py, num, expr) {
                e.print_and_set_sys_last_vars(py);
                // Write empty buffer on error to continue fuzzing
                self.write(b"");
            }
        });
    }

    fn script(&mut self, py: Python, num: usize, expr: PyObject) -> PyResult<()> {
        let bufs = self.buffers.split_off(self.buffers.len() - num);
        let byte_arrays: Vec<_> = bufs.into_iter()
            .map(|cur| PyBytes::new(py, &cur.into_inner()))
            .collect();

        for (name, func) in self.ctx.get_functions_in_scope().iter() {
            expr.getattr(py, "__globals__")?
                .downcast::<PyDict>(py)?
                .set_item(name, func)?;
        }

        // Register profiler hook to prevent timeouts
        register_profiler().unwrap();

        // Register allocator hooks to prevent OOM
        let mut allocator_raw = Box::new(AllocatorCtx::new(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_RAW));
        let mut allocator_mem = Box::new(AllocatorCtx::new(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_MEM));
        let mut allocator_obj = Box::new(AllocatorCtx::new(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_OBJ));

        register_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_RAW, allocator_raw.as_mut() as *mut _ as *mut c_void);
        register_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_MEM, allocator_mem.as_mut() as *mut _ as *mut c_void);
        register_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_OBJ, allocator_obj.as_mut() as *mut _ as *mut c_void);

        // Call the Python function
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let res = expr.call1(py, PyTuple::new(py, &byte_arrays));
            match res.and_then(|obj| {
                obj.extract::<&str>(py).map(|s| s.as_bytes().to_vec())
                    .or_else(|_| obj.extract::<&[u8]>(py).map(|s| s.to_vec()))
            }) {
                Ok(data) => { self.write(&data); }
                Err(e) => { println!("Caught python error: {:?}", e.to_string()) }
            };
        }));

        if let Err(panic) = res {
            if let Some(s) = panic.downcast_ref::<&str>() {
                println!("Caught panic: {}", s);
            } else if let Some(s) = panic.downcast_ref::<String>() {
                println!("Caught panic: {}", s);
            } else {
                println!("Caught panic: unknown");
            }
        }

        // Unregister allocator hooks
        unregister_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_RAW, &allocator_raw);
        unregister_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_MEM, &allocator_mem);
        unregister_allocator_hooks(ffi::PyMemAllocatorDomain::PYMEM_DOMAIN_OBJ, &allocator_obj);

        // Unregister profiler
        unregister_profiler().unwrap();

        Ok(())

    }

    fn push_buffer(&mut self) {
        self.buffers.push(std::io::Cursor::new(vec![]));
    }

    fn next_rule(&mut self, nt: NTermID) {
        let nid = NodeID::from(self.i);
        let rule: &'ctx Rule = self.tree.get_rule(nid, self.ctx);
        // assert_eq!(nt, rule.nonterm());
        if rule.nonterm() != nt {
            let actual_nt = self.ctx.nt_id_to_s(rule.nonterm());
            let expected_nt = self.ctx.nt_id_to_s(nt);
            panic!("Rule nonterm mismatch: {} (expected) != {} (actual) while processing NodeID {}", expected_nt, actual_nt, nid.to_i());
        }
        self.i += 1;
        match rule {
            Rule::Plain(r) => self.next_plain(r),
            Rule::Script(r) => self.next_script(r),
            Rule::Literal(_) => self.next_literal(self.tree.get_custom_rule_data(nid)),
            Rule::RegExp(_) => self.next_regexp(self.tree.get_custom_rule_data(nid)),
            Rule::Int(_) => self.next_int(self.tree.get_custom_rule_data(nid)),
            Rule::Bytes(_) => self.next_bytes(self.tree.get_custom_rule_data(nid)),
        }
    }

    fn next_literal(&mut self, data: &'tree [u8]) {
        self.stack.push(UnparseStep::<'data>::Bytes(&data));
    }

    fn next_int(&mut self, data: &'tree [u8]) {
        self.stack.push(UnparseStep::<'data>::Int(&data));
    }

    fn next_bytes(&mut self, data: &'tree [u8]) {
        self.stack.push(UnparseStep::<'data>::Bytes(&data));
    }

    fn next_plain(&mut self, r: &'ctx PlainRule) {
        for rule_child in r.children.iter().rev() {
            let op = match rule_child {
                RuleChild::Term(data) => UnparseStep::<'data>::Term(&data),
                RuleChild::NTerm(id) => UnparseStep::<'data>::Nonterm(*id),
            };
            self.stack.push(op);
        }
    }

    fn next_script(&mut self, r: &ScriptRule) {
        {
            Python::with_gil(|py|{
            self.stack.push(UnparseStep::Script(
                r.nonterms.len(),
                r.script.clone_ref(py),
            ));
            });
        }
        for nterm in r.nonterms.iter().rev() {
            self.stack.push(UnparseStep::Nonterm(*nterm));
            self.stack.push(UnparseStep::PushBuffer());
        }
    }

    fn next_regexp(&mut self, data: &'tree [u8]) {
        self.stack.push(UnparseStep::<'data>::Term(&data));
    }

    fn unparse(&mut self) -> NodeID {
        while self.unparse_step() {}
        return NodeID::from(self.i);
    }
}

struct LimitedVec {
    data: Vec<u8>,
    limit: usize,
    overflow: bool,
}

impl Write for LimitedVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.data.len() + buf.len() > self.limit {
            self.overflow = true;
            // Still return success to avoid panics
            return Ok(buf.len());
        }
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

pub trait TreeLike
where
    Self: Sized,
{
    fn get_rule_id(&self, n: NodeID) -> RuleID;
    fn size(&self) -> usize;
    fn to_tree(&self, _: &Context) -> Tree;
    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule;
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom;
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8];
    fn get_nonterm_id(&self, n: NodeID, ctx: &Context) -> NTermID {
        self.get_rule(n, ctx).nonterm()
    }

    fn unparse<W: Write>(&self, id: NodeID, ctx: &Context, mut w: &mut W) {
        Unparser::new(id, &mut w, self, ctx).unparse();
    }

    fn unparse_to<W: Write>(&self, ctx: &Context, w: &mut W) {
        self.unparse(NodeID::from(0), ctx, w);
    }

    fn unparse_to_vec(&self, ctx: &Context) -> Vec<u8> {
        self.unparse_node_to_vec(NodeID::from(0), ctx)
    }

    fn unparse_node_to_vec(&self, n: NodeID, ctx: &Context) -> Vec<u8> {
        let mut writer = LimitedVec {
            data: Vec::with_capacity(4096),
            limit: 2 << 20,
            overflow: false,
        };
        self.unparse(n, ctx, &mut writer);
        if writer.overflow {
            eprintln!("Warning: Unparse output exceeded limit of {} bytes, truncating.", writer.limit);
        }
        writer.data
    }

    fn unparse_print(&self, ctx: &Context) {
        self.unparse_to(ctx, &mut io::stdout());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tree {
    pub rules: Vec<RuleIDOrCustom>,
    pub sizes: Vec<usize>,
    pub paren: Vec<NodeID>,
}

impl TreeLike for Tree {
    fn get_rule_id(&self, n: NodeID) -> RuleID {
        self.rules[n.to_i()].id()
    }

    fn size(&self) -> usize {
        return self.rules.len();
    }

    fn to_tree(&self, _ctx: &Context) -> Tree {
        return self.clone();
    }

    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule {
        return ctx.get_rule(self.get_rule_id(n));
    }
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8] {
        self.rules[n.to_i()].data()
    }
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom {
        &self.rules[n.to_i()]
    }
}

impl Tree {
    pub fn from_rule_vec(rules: Vec<RuleIDOrCustom>, ctx: &Context) -> Self {
        let sizes = vec![0; rules.len()];
        let paren = vec![NodeID::from(0); rules.len()];
        let mut res = Tree {
            rules,
            sizes,
            paren,
        };
        if res.rules.len() > 0 {
            res.calc_subtree_sizes_and_parents(ctx);
        }
        return res;
    }

    pub fn get_rule_id(&self, n: NodeID) -> RuleID {
        return self.rules[n.to_i()].id();
    }

    pub fn subtree_size(&self, n: NodeID) -> usize {
        return self.sizes[n.to_i()];
    }

    pub fn mutate_replace_from_tree<'a>(
        &'a self,
        n: NodeID,
        other: &'a Tree,
        other_node: NodeID,
    ) -> TreeMutation<'a> {
        let old_size = self.subtree_size(n);
        let new_size = other.subtree_size(other_node);
        return TreeMutation {
            prefix: self.slice(0.into(), n),
            repl: other.slice(other_node, other_node + new_size),
            postfix: self.slice(n + old_size, self.rules.len().into()),
        };
    }

    fn calc_subtree_sizes_and_parents(&mut self, ctx: &Context) {
        self.calc_parents(ctx);
        self.calc_sizes();
    }

    fn calc_parents(&mut self, ctx: &Context) {
        if self.size() == 0 {
            return;
        }
        let mut stack: Vec<(NTermID, NodeID)> = Vec::new();
        stack.push((
            self.get_rule(NodeID::from(0), ctx).nonterm(),
            NodeID::from(0),
        ));
        for i in 0..self.size() {
            let node_id = NodeID::from(i);
            let nonterm = self.get_rule(node_id, ctx).nonterm();
            //sanity check
            let (nterm_id, node) = stack.pop().expect("Not a valid tree for unparsing!");
            if nterm_id != nonterm {
                panic!("Not a valid tree for unparsing because in i={} {:?} != {:?}", i, nterm_id, nonterm);
            } else {
                self.paren[i] = node;
            }
            let rule = self.get_rule(node_id, ctx);
            for nonterm in rule.nonterms().iter().rev() {
                stack.push((*nonterm, node_id));
            }
        }
    }

    fn calc_sizes(&mut self) {
        //Initiate with 1
        for size in self.sizes.iter_mut() {
            *size = 1;
        }
        for i in (1..self.size()).rev() {
            self.sizes[self.paren[i].to_i()] += self.sizes[i];
        }
    }

    fn slice(&self, from: NodeID, to: NodeID) -> &[RuleIDOrCustom] {
        return &self.rules[from.into()..to.into()];
    }

    pub fn get_parent(&self, n: NodeID) -> Option<NodeID> {
        if n != NodeID::from(0) {
            return Some(self.paren[n.to_i()]);
        }
        return None;
    }

    pub fn truncate(&mut self) {
        self.rules.truncate(0);
        self.sizes.truncate(0);
        self.paren.truncate(0);
    }

    pub fn generate_from_nt(&mut self, start: NTermID, len: usize, ctx: &Context) {
        let ruleid = ctx.get_random_rule_for_nt(start, len);
        self.generate_from_rule(ruleid, len - 1, ctx);
    }

    pub fn generate_from_rule(&mut self, ruleid: RuleID, max_len: usize, ctx: &Context) {
        match ctx.get_rule(ruleid) {
            Rule::Plain(..) | Rule::Script(..) => {
                self.truncate();
                self.rules.push(RuleIDOrCustom::Rule(ruleid));
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                ctx.get_rule(ruleid).generate(self, &ctx, max_len);
                self.sizes[0] = self.rules.len();
            }
            Rule::Literal(LiteralRule { base , ..}) => {
                let rid = RuleIDOrCustom::Custom(
                    ruleid,
                    base.clone(),
                );
                self.truncate();
                self.rules.push(rid.clone());
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                self.sizes[0] = self.rules.len();
            },
            Rule::RegExp(RegExpRule { hir, .. }) => {
                let rid = RuleIDOrCustom::Custom(
                    ruleid,
                    regex_mutator::generate(hir, thread_rng().gen::<u64>()),
                );
                self.truncate();
                self.rules.push(rid);
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                self.sizes[0] = self.rules.len();
            },
            Rule::Int(IntRule { bits , ..}) => {
                let rid = RuleIDOrCustom::Custom(
                    ruleid,
                    regex_mutator::dumbass_generator_int(*bits)
                );
                self.truncate();
                self.rules.push(rid.clone());
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                self.sizes[0] = self.rules.len();
            },
            Rule::Bytes(BytesRule { len, ..}) => {
                let rid = RuleIDOrCustom::Custom(
                    ruleid,
                    regex_mutator::dumbass_generator_bytes(*len)
                );
                self.truncate();
                self.rules.push(rid);
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                self.sizes[0] = self.rules.len();
            },
        }
    }

    pub fn calc_recursions(&self, ctx: &Context) -> Option<Vec<RecursionInfo>> {
        let mut ret = Vec::new();
        let mut done_nterms = HashSet::new();
        for rule in &self.rules {
            let nterm = ctx.get_nt(&rule);
            if !done_nterms.contains(&nterm) {
                match RecursionInfo::new(self, nterm, ctx) {
                    Some(rec_info) => ret.push(rec_info),
                    None => {}
                }
                done_nterms.insert(nterm);
            }
        }
        if ret.is_empty() {
            return None;
        }
        return Some(ret);
    }

    fn _find_recursions_iter(&self, ctx: &Context) -> Vec<(NodeID, NodeID)> {
        let mut found_recursions = Vec::new();
        //Only search for iterations for up to 10000 nodes
        for i in 1..cmp::min(self.size(), 10000) {
            let node_id = NodeID::from(self.size() - i);
            let current_nterm: NTermID = self.get_rule(node_id, ctx).nonterm();
            let mut current_node_id = self.paren[node_id.to_i()];
            let mut depth = 0;
            while current_node_id != NodeID::from(0) {
                if self.get_rule(current_node_id, ctx).nonterm() == current_nterm {
                    found_recursions.push((current_node_id, node_id));
                }
                current_node_id = self.paren[current_node_id.to_i()];
                if depth > 15 {
                    break;
                }
                depth += 1;
            }
        }
        return found_recursions;
    }

    pub fn set_custom_rule(&mut self, n: NodeID, r: RuleID, data: Vec<u8>) {
        self.rules[n.to_i()] = RuleIDOrCustom::Custom(r, data);
    }
}

pub struct TreeMutation<'a> {
    pub prefix: &'a [RuleIDOrCustom],
    pub repl: &'a [RuleIDOrCustom],
    pub postfix: &'a [RuleIDOrCustom],
}

impl<'a> TreeMutation<'a> {
    pub fn get_at(&self, n: NodeID) -> &'a RuleIDOrCustom {
        let i = n.to_i();
        let end0 = self.prefix.len();
        let end1 = end0 + self.repl.len();
        let end2 = end1 + self.postfix.len();
        if i < end0 {
            return &self.prefix[i];
        }
        if i < end1 {
            return &self.repl[i - end0];
        }
        if i < end2 {
            return &self.postfix[i - end1];
        }
        panic!("index out of bound for rule access");
    }
}

impl<'a> TreeLike for TreeMutation<'a> {
    fn get_rule_id(&self, n: NodeID) -> RuleID {
        return self.get_at(n).id();
    }

    fn size(&self) -> usize {
        return self.prefix.len() + self.repl.len() + self.postfix.len();
    }
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom {
        self.get_at(n)
    }

    fn to_tree(&self, ctx: &Context) -> Tree {
        let mut vec = vec![];
        vec.extend_from_slice(&self.prefix);
        vec.extend_from_slice(&self.repl);
        vec.extend_from_slice(&self.postfix);
        return Tree::from_rule_vec(vec, ctx);
    }

    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule {
        return ctx.get_rule(self.get_rule_id(n));
    }
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8] {
        self.get_at(n).data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::Context;
    use newtypes::NodeID;

    fn calc_subtree_sizes_and_parents_rec_test(tree: &mut Tree, n: NodeID, ctx: &Context) -> usize {
        let mut cur = n + 1;
        let mut size = 1;
        for _ in 0..tree.get_rule(n, ctx).number_of_nonterms() {
            tree.paren[cur.to_i()] = n;
            let sub_size = calc_subtree_sizes_and_parents_rec_test(tree, cur, ctx);
            cur = cur + sub_size;
            size += sub_size;
        }
        tree.sizes[n.to_i()] = size;
        return size;
    }

    #[test]
    fn check_calc_sizes_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            calc_subtree_sizes_and_parents_rec_test(&mut tree, NodeID::from(0), &ctx);
            let vec1 = tree.sizes.clone();
            tree.calc_sizes();
            let vec2 = tree.sizes.clone();
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_calc_paren_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            calc_subtree_sizes_and_parents_rec_test(&mut tree, NodeID::from(0), &ctx);
            let vec1 = tree.paren.clone();
            tree.calc_parents(&ctx);
            let vec2 = tree.paren.clone();
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_unparse_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            let mut vec1 = vec![];
            let mut vec2 = vec![];
            tree.unparse(NodeID::from(0), &ctx, &mut vec1);
            tree.unparse(NodeID::from(0), &ctx, &mut vec2);
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_find_recursions() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c");
        let _ = ctx.add_rule("B", b"b{A}b");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a");
        ctx.initialize(20);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        let mut some_recursions = false;
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 20, &ctx);
            if let Some(recursions) = tree.calc_recursions(&ctx) {
                assert_ne!(recursions.len(), 0);
                for recursion_info in recursions {
                    for offset in 0..recursion_info.get_number_of_recursions() {
                        let tuple = recursion_info.get_recursion_pair_by_offset(offset);
                        some_recursions = true;
                        assert!(tuple.0.to_i() < tuple.1.to_i());
                    }
                }
            }
        }
        assert!(some_recursions);
    }
}
