import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

predicate allocatingFunction(Function f) {
  f.hasGlobalName("malloc") or
  f.hasGlobalName("calloc") or
  f.hasGlobalName("valloc") or
  f.hasGlobalName("realloc") or
  f.getName().matches("%alloc%")
}

predicate aPartOfExpr(Expr child, Expr parent) { parent = child or parent.getAChild() = child }

module AllocCheckFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(IfStmt s |
      aPartOfExpr(source.asExpr(), s.getCondition()) 
      // and s.getEnclosingFunction().getName().matches("%rot%")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      (
        sink.asExpr() = fc.getAnArgument() or
        aPartOfExpr(sink.asExpr(), fc.getAnArgument())
      ) and
      allocatingFunction(fc.getTarget())
    )
    and
    1 = 1
  }
}

module AllocCheckFlow = TaintTracking::Global<AllocCheckFlowConfig>;

import AllocCheckFlow::PathGraph

from Call allocCall, Expr check, DataFlow::Node source, DataFlow::Node sink
where
  source.asExpr() = check and
  aPartOfExpr(sink.asExpr(), allocCall.getAnArgument()) and
  AllocCheckFlow::flow(source, sink) and
  allocCall.getEnclosingFunction() = check.getEnclosingFunction()
select sink.getLocation() as alloc, check.getLocation() as access,
  allocCall.getEnclosingFunction().getLocation() as id,
  allocCall.getEnclosingFunction().getName() as name,
  check.getEnclosingFunction().getName() as checkname,
  "access the check of size before alloc call denoted as alloc in identified function" as note
// from Function f, IfStmt c
// where f.hasGlobalName("rot13func") and c.getEnclosingFunction() = f
// select f, c, c.getCondition()