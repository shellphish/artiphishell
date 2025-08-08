import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

predicate edge(Function src, Function dst) {
  src = dst or
  allCalls(src, dst)
}

predicate allocatingFunction(Function f) {
  f.hasGlobalName("malloc") or
  f.hasGlobalName("calloc") or
  f.hasGlobalName("valloc") or
  f.hasGlobalName("realloc")
}

predicate allocatingFunction1(Function f) { f.hasGlobalName("aligned_alloc") }

predicate allocatingFunction2(Function f) {
  f.hasGlobalName("memalign") or
  f.hasGlobalName("posix_memalign")
}

predicate callsAllocationEventually(Function caller) {
  exists(Function alloc |
    edge(caller, alloc) and
    allocatingFunction(alloc)
  )
}

predicate exprIsConst(Expr e) {
  e instanceof Literal
  or
  e instanceof SizeofTypeOperator
  or
  // exprIsConst(e.(MulExpr).getLeftOperand()) and
  // exprIsConst(e.(MulExpr).getRightOperand())
  // or
  exprIsConst(e.(BinaryOperation).getLeftOperand()) and
  exprIsConst(e.(BinaryOperation).getRightOperand())
  or
  exprIsConst(e.(AssignExpr).getRValue())
}

predicate allocWithConst(Function f, Call allocCall) {
  allocCall.getEnclosingFunction() = f and
  callsAllocationEventually(allocCall.getTarget()) and
  exprIsConst(allocCall.getArgument(0))
}

boolean const(Expr e) {
  result = true and exprIsConst(e)
  or
  result = false and not exprIsConst(e)
}

module ConstAllocFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof Literal }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      sink.asExpr() = fc.getArgument(0) and
      allocatingFunction(fc.getTarget())
      or
      sink.asExpr() = fc.getArgument(1) and
      allocatingFunction1(fc.getTarget())
      or
      sink.asExpr() = fc.getArgument(2) and
      allocatingFunction2(fc.getTarget())
    )
  }
}

module ConstAllocFlow = DataFlow::Global<ConstAllocFlowConfig>;

import ConstAllocFlow::PathGraph

from Call allocCall, Expr literal, DataFlow::Node source, DataFlow::Node sink
where
  source.asExpr() = literal and
  sink.asExpr() = allocCall.getAnArgument() and
  ConstAllocFlow::flow(source, sink)
select allocCall, literal.getLocation() as access,
  literal.getEnclosingFunction().getLocation() as func
// from Expr expr
// select expr, const(expr), expr.getFile()
