import cpp

class StackAlloc extends DeclStmt {
  //   StackAlloc() { this instanceof DeclStmt and this.(DeclStmt).getDeclarationEntry(0).getType() instanceof ArrayType }
  VariableDeclarationEntry asVariableDeclarationEntry() {
    exists(VariableDeclarationEntry d |
      this.getADeclarationEntry() = d and
      d.getType() instanceof ArrayType and
      result = d
    )
  }
}

int getArraySize(VariableDeclarationEntry v) {
  result = v.getType().(ArrayType).getSize()
  //https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/Type.qll/predicate.Type$ArrayType$getSize.0.html
}


class UnsafeFunc extends Function {
  // todo: verify the alloc to be constant and find it being written
  StackAlloc getStackAlloc() {
    exists(StackAlloc s | s.getEnclosingFunction() = this and result = s)
  }
}

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
    deref.getArrayBase() = a
    and (
      // Currently we want only not constant array offset, but it will be good
      // to check if constant offset is within array bounds
      not deref.getArrayOffset() instanceof Literal
    )
  )
}

predicate eventuallyAccessed(Expr e, Variable p) {
  e instanceof PointerDereferenceExpr and eventuallyDereferenced(e, p)
  or
  e instanceof ArrayExpr and eventuallyArrayAccess(e, p)
}

from UnsafeFunc f, StackAlloc s, VariableDeclarationEntry v, Expr a
where
  f.getStackAlloc() = s and
  s.asVariableDeclarationEntry() = v and
  eventuallyAccessed(a, v.getVariable())
select f.getLocation() as id, f.getName() as name,
  "This function has constant allocation on stack." as note, v as dec, getArraySize(v) as size,
  a.getLocation() as access
