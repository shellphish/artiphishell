import cpp

predicate eventuallyDereferenced(PointerDereferenceExpr deref, Variable p) {
  exists(VariableAccess a |
    a.getTarget() = p and
    deref.getOperand() = a
  )
  or
  eventuallyDereferenced(deref.getOperand().(UnaryOperation), p)
}

predicate eventuallyArrayAccess(ArrayExpr deref, Variable p) {
  exists(VariableAccess a |
    a.getTarget() = p and
    deref.getArrayBase() = a and
    // Currently we want only not constant array offset, but it will be good
    // to check if constant offset is within array bounds
    not deref.getArrayOffset() instanceof Literal
  )
}

predicate eventuallyAccessed(Expr e, Variable p) {
  e instanceof PointerDereferenceExpr and eventuallyDereferenced(e, p)
  or
  e instanceof ArrayExpr and eventuallyArrayAccess(e, p)
}

predicate checkedVariable(Expr e, Expr a) {
  (
    e = a or
    checkedVariable(e.(BinaryOperation).getLeftOperand(), a) or
    checkedVariable(e.(BinaryOperation).getRightOperand(), a) or
    checkedVariable(e.(UnaryOperation).getOperand(), a)
  ) and
  not e instanceof PointerDereferenceExpr
}

predicate nullChecked(Expr e, Variable p) {
  exists(Stmt ifOrWhile, Expr a |
    (
      a.(VariableAccess).getTarget() = p or
      a.(ArrayExpr).getArrayBase().(VariableAccess).getTarget() = p
    ) and
    (checkedVariable(ifOrWhile.(IfStmt).getCondition(), a)
    or checkedVariable(ifOrWhile.(WhileStmt).getCondition(), a)) and
    a.getLocation().getStartLine() < e.getLocation().getStartLine()
  )
}

from Expr e, Variable p, Function f
where eventuallyAccessed(e, p) and e.getEnclosingFunction() = f and not nullChecked(e, p)
select f.getLocation() as id, f.getName() as name, "Potential null pointer dereference." as note,
  e.getLocation() as access, p as pointer
