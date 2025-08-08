import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

/** Identify the standard free() function. */
predicate isFreeFunction(Function f) { f.hasGlobalName("free") }

/** A value passed to free(). */
predicate isFreedPointer(DataFlow::Node node) {
  exists(FunctionCall call |
    isFreeFunction(call.getTarget()) and
    node.asExpr() = call.getArgument(0)
  )
}

/** An expression that dereferences a pointer. */
predicate isDeref(DataFlow::Node node) {
  exists(Expr e |
    node.asExpr() = e and
    dereferenced(e)
  )
}

module DfFlowConfig implements DataFlow::ConfigSig {
  predicate isSink(DataFlow::Node source) { isFreedPointer(source) }

  predicate isSource(DataFlow::Node sink) { isFreedPointer(sink) }
}

module DfFlow = DataFlow::Global<DfFlowConfig>;

from DataFlow::Node src, DataFlow::Node sink
where DfFlow::flow(src, sink) and src != sink
select sink as access, src as source, sink.asExpr().getEnclosingFunction().getLocation() as id,
  sink.asExpr().getEnclosingFunction().getName() as name,
  "Free of memory that may have been freed." as note
