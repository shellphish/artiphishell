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

Variable getVariable(VariableDeclarationEntry v) { result = v.getVariable() }

class UnsafeFunc extends Function {
  // todo: verify the alloc to be constant and find it being written
  StackAlloc getStackAlloc() {
    exists(StackAlloc s | s.getEnclosingFunction() = this and result = s)
  }
}

Expr variableUsedInLoop(Variable v) {
  exists(VariableAccess a, ForStmt forLoop |
    forLoop.getEnclosingFunction() = a.getEnclosingFunction() and
    forLoop.getLocation().getStartLine() <= a.getLocation().getStartLine() and
    forLoop.getLocation().getEndLine() >= a.getLocation().getEndLine() and
    a.getTarget() = v and
    result = a
  )
}

from UnsafeFunc f, StackAlloc s, VariableDeclarationEntry v
where f.getStackAlloc() = s and s.asVariableDeclarationEntry() = v
select f.getLocation() as id, f.getName() as name, "This function has allocation on stack and looped through it." as note, v.getLocation() as declaration,
  getArraySize(v) as size, getVariable(v).getLocation() as var, variableUsedInLoop(v.getVariable()).getLocation() as access