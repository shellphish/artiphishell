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

module UafFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFreedPointer(source) }

  predicate isSink(DataFlow::Node sink) { isDeref(sink) }
}

module UafFlow = DataFlow::Global<UafFlowConfig>;

from DataFlow::Node src, DataFlow::Node sink
where UafFlow::flow(src, sink)
select sink as access, src as source, sink.asExpr().getEnclosingFunction().getLocation() as id,
  sink.asExpr().getEnclosingFunction().getName() as name,
  "Dereference of memory that may have been freed here." as note
