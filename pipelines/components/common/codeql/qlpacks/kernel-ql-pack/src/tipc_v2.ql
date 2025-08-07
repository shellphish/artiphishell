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

module MemcpySizeFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof LocalFlowSource
  }

  int fieldFlowBranchLimit() { result = 5000 }

  predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      sink.asExpr() = fc.getArgument(2) and
      fc.getTarget().hasName("memcpy"))
  }
}

module MallocSizeFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof LocalFlowSource
  }

  int fieldFlowBranchLimit() { result = 5000 }

  predicate isSink(DataFlow::Node sink) {
    exists(MallocFunctionCall call, Expr val | val = sink.asExpr() |
      val = call.getArgument(0)
    )
    // exists (FunctionCall fc |
    //   sink.asExpr() = fc.getArgument(0) and
    //   fc.getTarget().hasName("malloc")
    // )
  }
}

module MemcpyPtrFlowConfiguration implements DataFlow::ConfigSig {

  // taint the output of the malloc call
  predicate isSource(DataFlow::Node source) { 
    exists (MallocFunctionCall call |
      source.asExpr() = call
    )
  }

  int fieldFlowBranchLimit() { result = 5000 }


  predicate isSink(DataFlow::Node sink) {
    exists (FunctionCall fc |
      (
        sink.asExpr() = fc.getArgument(0) or 
        sink.asExpr() = fc.getArgument(1)
      ) and
      fc.getTarget().hasName("memcpy"))
  }
}

predicate isFunction(FunctionCall call, string name) {
  call.getTarget().hasGlobalName(name)
}

class MemcpyFunctionCall extends FunctionCall {
  MemcpyFunctionCall() { isFunction(this, "memcpy") }
}

class MallocFunctionCall extends FunctionCall {
  MallocFunctionCall() { isFunction(this, "malloc") }
}

module MemcpySizeFlow = DataFlow::Global<MemcpySizeFlowConfiguration>;
module MallocSizeFlow = DataFlow::Global<MallocSizeFlowConfiguration>;
module MemcpyPtrFlow = DataFlow::Global<MemcpyPtrFlowConfiguration>;

int explorationLimit() { result = 20 }

// module MyPartialFlow = MallocSizeFlow::FlowExplorationFwd<explorationLimit/0>;
module MyPartialFlow = MallocSizeFlow::FlowExplorationRev<explorationLimit/0>;

predicate adhocPartialFlow(Function f, MyPartialFlow::PartialPathNode n, DataFlow::Node src, int dist) {
  exists(MyPartialFlow::PartialPathNode source |
    MyPartialFlow::partialFlow(source, n, dist) and
    src = source.getNode() and
    f = n.getNode().getEnclosingCallable()
  )
}



// from DataFlow::Node src, DataFlow::Node sink
// where MemcpySizeFlow::flow(src, sink)
// select src.asExpr(), sink.asExpr(), "found flow to malloc"

// from MemcpyFunctionCall memcpy, MallocFunctionCall malloc, string msg2// , string msg2// , string msg3
// where
//   exists ( Expr sizeArg | 
//     sizeArg = memcpy.getArgument(2) and
//     MemcpySizeFlow::flowToExpr(sizeArg) and
//     msg2 = "found flow to " + memcpy.toString()  
//   )  
//   // exists ( Expr sizeArg |
//   //   sizeArg = malloc.getArgument(0) and
//   //   MallocSizeFlow::flowToExpr(sizeArg) and
//   //   msg2 = "found flow to " + malloc.toString()
//   // )
//   // ) and 
//   // exists ( Expr ptrArg |
//   //   ptrArg = malloc and
//   //   MemcpyPtrFlow::flowToExpr(ptrArg) and
//   //   msg3 = "found flow to " + malloc.toString()
//   // )
// select memcpy, "asd", msg2, "asd"


from DataFlow::Node source, DataFlow::Node sink, MallocSizeFlow::PathNode sourceNode, MallocSizeFlow::PathNode sinkNode
where
  source = sourceNode.getNode() and
  sink = sinkNode.getNode() and
  MallocSizeFlow::flowPath(sourceNode, sinkNode)
select sink, sourceNode, sinkNode, "found flow to malloc"

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