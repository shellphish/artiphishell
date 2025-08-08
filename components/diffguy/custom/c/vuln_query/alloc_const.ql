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
  f.hasGlobalName("realloc") or
  f.hasGlobalName("valloc") 
}

predicate allocatingFunction1(Function f) {
  f.hasGlobalName("memalign") or 
  f.hasGlobalName("posix_memalign") or 
  f.hasGlobalName("aligned_alloc") 
}


predicate callsAllocationEventually(Function caller) {
  exists(Function alloc |
    edge(caller, alloc) and
   allocatingFunction(alloc)
  )
}

predicate callsAllocationEventually1(Function caller) {
  exists(Function alloc |
    edge(caller, alloc) and
  allocatingFunction1(alloc)
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
  (callsAllocationEventually(allocCall.getTarget()) and
  exprIsConst(allocCall.getArgument(0))) or (
    callsAllocationEventually1(allocCall.getTarget()) and
    exprIsConst(allocCall.getArgument(1))
  )
}

boolean const(Expr e) {
  result = true and exprIsConst(e)
  or
  result = false and not exprIsConst(e)
}

from Function func, Call allocCall
where allocWithConst(func, allocCall)// and func.getName().matches("%_cupsBuffer%")
select func.getLocation() as id, func.getName() as name, "This function called alloc with constant." as note, allocCall.getLocation() as allocPosition
// from Expr expr
// select expr, const(expr), expr.getFile()