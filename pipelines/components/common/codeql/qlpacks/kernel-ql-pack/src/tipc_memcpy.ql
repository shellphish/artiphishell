/**
 * @id all-syscalls
 * @kind path-problem
 * @problem.severity error
 * 
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.security.Security

private class SyscallFunction extends Function {
  SyscallFunction() {
    exists(MacroInvocation m |
      m.getMacro().getName().matches("SYSCALL\\_DEFINE%") and
      this = m.getEnclosingFunction()
    )
  }
}

private class SyscallArgSource extends RemoteFlowSource {
  SyscallArgSource() {
    exists(Function syscall, Parameter param |
      syscall instanceof SyscallFunction and
      syscall.getAParameter() = param and
      (
        this.asParameter(0) = param or
        this.asParameter(1) = param or
        this.asParameter(2) = param
      )
    )
  }

  override string getSourceType() { result = "syscall arg" }
}

// class BugArgSource extends RemoteFlowSource {
//   BugArgSource() {
//     exists(Function targetfn, Parameter param |
//       targetfn.hasGlobalName("tipc_crypto_key_rcv") and
//       targetfn.getAParameter() = param and
//       ( 
//         this.asParameter(0) = param or
//         this.asParameter(1) = param or
//         this.asParameter(2) = param
//       )
//     )
//   }

//   override string getSourceType() { result = "tipc argument" }
// }


predicate isFlowSource(FlowSource source, string sourceType) { sourceType = source.getSourceType() }

module MemcpySizeFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFlowSource(source, "tipc argument") }

  predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      sink.asExpr() = fc.getArgument(2) and
      fc.getTarget().hasName("memcpy"))
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(FieldAccess fa |
      n1.asIndirectExpr() = fa.getQualifier() and
      n2.asIndirectExpr() = fa
    )
  }
}

module MallocSizeFlowConfiguration implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) { isFlowSource(source, "tipc argument") }

  predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      sink.asExpr() = fc.getArgument(0) and
      fc.getTarget().hasName("kmalloc")
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(FieldAccess fa |
      n1.asIndirectExpr() = fa.getQualifier() and
      n2.asIndirectExpr() = fa
    )
  }
}

module MemcpyPtrFlowConfiguration implements DataFlow::ConfigSig {

  // taint the output of the malloc call
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(Call).getTarget().hasName("kmalloc") or
    source.asIndirectExpr().(Call).getTarget().hasName("kmalloc")
  }

  predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      (
        sink.asExpr() = fc.getArgument(0) or 
        sink.asExpr() = fc.getArgument(1) or 
        sink.asIndirectExpr() = fc.getArgument(0) or
        sink.asIndirectExpr() = fc.getArgument(1)
      ) and
      fc.getTarget().hasName("memcpy"))
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(FieldAccess fa |
      n1.asIndirectExpr() = fa.getQualifier() and
      n2.asIndirectExpr() = fa
    )
  }

}

predicate isFunction(FunctionCall call, string name) {
  call.getTarget().hasGlobalName(name)
}

class MemcpyFunctionCall extends FunctionCall {
  MemcpyFunctionCall() { isFunction(this, "memcpy") }
}

class MallocFunctionCall extends FunctionCall {
  MallocFunctionCall() { isFunction(this, "kmalloc") }
}

module MemcpySizeFlow = TaintTracking::Global<MemcpySizeFlowConfiguration>;
module MallocSizeFlow = TaintTracking::Global<MallocSizeFlowConfiguration>;
module MemcpyPtrFlow = TaintTracking::Global<MemcpyPtrFlowConfiguration>;

predicate isMemcpyPtr(MemcpyFunctionCall f, MemcpyPtrFlow::PathNode argNode) {
  exists( DataFlow::Node arg |
      arg = argNode.getNode() and 
      (
        arg.asExpr() = f.getArgument(0) or 
        arg.asExpr() = f.getArgument(1) or 
        arg.asIndirectExpr() = f.getArgument(0) or
        arg.asIndirectExpr() = f.getArgument(1)
      )
    )
} 

predicate isMallocPointer(MallocFunctionCall f, MemcpyPtrFlow::PathNode argNode) {
  exists ( DataFlow::Node arg |
      arg = argNode.getNode() and
      ( 
        arg.asExpr() = f or 
        arg.asIndirectExpr() = f 
      )
  )
}

from MemcpyFunctionCall memcpy, MallocFunctionCall malloc, DataFlow::Node source, DataFlow::Node sink, string msg3
where
  exists ( Expr sizeArg | 
    sizeArg = memcpy.getArgument(2) and
    MemcpySizeFlow::flowToExpr(sizeArg) and
    // msg1 = "found flow to " + memcpy.toString()  
    source.asExpr() = sizeArg
  ) and 
  exists ( Expr sizeArg |
    sizeArg = malloc.getArgument(0) and
    MallocSizeFlow::flowToExpr(sizeArg) and
    // msg2 = "found flow to " + malloc.toString()
    sink.asExpr() = sizeArg 
  ) and 
  exists ( MemcpyPtrFlow::PathNode srcNode, MemcpyPtrFlow::PathNode sinkNode |
    isMemcpyPtr(memcpy, sinkNode) and
    isMallocPointer(malloc, srcNode) and
    MemcpyPtrFlow::flowPath(srcNode, sinkNode) and
    msg3 = "found flow to " + malloc.toString()
  )
select sink, source, memcpy, msg3

// from DataFlow::Node source, DataFlow::Node sink, MallocSizeFlow::PathNode sourceNode, MallocSizeFlow::PathNode sinkNode
// where
//   source = sourceNode.getNode() and
//   sink = sinkNode.getNode() and
//   MallocSizeFlow::flowPath(sourceNode, sinkNode)
// select sink, sourceNode, sinkNode, "found flow to malloc"

// from DataFlow::Node source, DataFlow::Node sink, MemcpyPtrFlow::PathNode sourceNode, MemcpyPtrFlow::PathNode sinkNode
// where
//   source = sourceNode.getNode() and
//   sink = sinkNode.getNode() and
//   MemcpyPtrFlow::flowPath(sourceNode, sinkNode)
// select sink, sourceNode, sinkNode, "found flow to malloc"

// from DataFlow::Node source, DataFlow::Node sink, MemcpySizeFlow::PathNode sourceNode, MemcpySizeFlow::PathNode sinkNode
// where
//   source = sourceNode.getNode() and
//   sink = sinkNode.getNode() and
//   MemcpySizeFlow::flowPath(sourceNode, sinkNode)
// select sink, sourceNode, sinkNode, "found flow to malloc"

// int explorationLimit() { result = 20 }

// module MyPartialFlow = MemcpySizeFlow::FlowExplorationFwd<explorationLimit/0>;
// // module MyPartialFlow = MallocSizeFlow::FlowExplorationRev<explorationLimit/0>;

// predicate adhocPartialFlow(Function f, MyPartialFlow::PartialPathNode n, DataFlow::Node src, int dist) {
//   exists(MyPartialFlow::PartialPathNode source |
//     MyPartialFlow::partialFlow(source, n, dist) and
//     src = source.getNode() and
//     f = n.getNode().getEnclosingCallable()
//   )
// }

// from DataFlow::Node src, DataFlow::Node sink
// where MemcpySizeFlow::flow(src, sink)
// select src.asExpr(), sink.asExpr(), "found flow to malloc"