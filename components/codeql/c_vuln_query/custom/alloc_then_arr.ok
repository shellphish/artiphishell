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
  f.hasGlobalName("realloc")
}

predicate callsAllocationEventually(Function caller) {
  exists(Function alloc |
    edge+(caller, alloc) and
    allocatingFunction(alloc)
  )
}

predicate eventuallyDereferenced(PointerDereferenceExpr deref, Variable p) {
  exists(VariableAccess a |
    a.getTarget() = p and
    deref.getOperand() = a
  )
  or
  eventuallyDereferenced(deref.getOperand().(UnaryOperation), p)
}

predicate dereferencedInFor(Variable p, ForStmt forLoop, PointerDereferenceExpr deref) {
  eventuallyDereferenced(deref, p) and
  deref.getEnclosingFunction() = forLoop.getEnclosingFunction() and
  // Ok this is stupid
  deref.getLocation().getStartLine() > forLoop.getLocation().getStartLine() and
  deref.getLocation().getEndLine() < forLoop.getLocation().getEndLine()
}


predicate arrayExpInFor(Variable p, ForStmt forLoop, ArrayExpr deref) {
  exists(VariableAccess a |
    a.getTarget() = p and
    deref.getArrayBase() = a
  ) and
  deref.getEnclosingFunction() = forLoop.getEnclosingFunction() and
  // Ok this is stupid
  deref.getLocation().getStartLine() > forLoop.getLocation().getStartLine() and
  deref.getLocation().getEndLine() < forLoop.getLocation().getEndLine()
}

predicate forLoopAfterAlloc(
  Function f, Call allocCall, VariableAccess p, Expr deref
) {
  exists(ForStmt forLoop |
    allocCall.getEnclosingFunction() = f and
    forLoop.getEnclosingFunction() = f and
    callsAllocationEventually(allocCall.getTarget()) and
    allocCall.getLocation().getStartLine() < forLoop.getLocation().getStartLine() and
    (
      deref instanceof PointerDereferenceExpr and
      dereferencedInFor(p.getTarget(), forLoop, deref)
      and 1=0
      or
      deref instanceof ArrayExpr and
      arrayExpInFor(p.getTarget(), forLoop, deref)
    )
  )
}

from Function func, Call allocCall, AssignExpr allocExpr, Expr derefExpr
where
  forLoopAfterAlloc(func, allocCall, allocExpr.getLValue(), derefExpr) and
  // candidate.getName().matches("%validate%") and
  allocExpr.getRValue() = allocCall and
  allocExpr.getLValue() instanceof VariableAccess
select func.getLocation() as id, "This function has a 'for' loop after an allocating function." as note //, derefExpr