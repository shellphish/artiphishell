import cpp
// Do not use: risk of OOM

query predicate enclosingVar(VariableAccess va, GlobalVariable dst, Variable v){
  va.getEnclosingVariable() = v and
  va.getTarget() = dst
}

query predicate enclosingGVar(VariableAccess va, GlobalVariable dst, GlobalVariable v){
  va.getEnclosingVariable() = v and
  va.getTarget() = dst
}

query predicate enclosingFunc(VariableAccess va, GlobalVariable dst, Function v){
  va.getEnclosingFunction() = v and
  va.getTarget() = dst
}

query predicate enclosingElem(VariableAccess va, GlobalVariable dst, Element v){
  va.getEnclosingElement() = v and
  va.getTarget() = dst
}

query predicate enclosingStmt(VariableAccess va, GlobalVariable dst, Stmt v){
  va.getEnclosingStmt() = v and
  va.getTarget() = dst
}

query predicate enclosingDecl(VariableAccess va, GlobalVariable dst, Declaration v){
  va.getEnclosingDeclaration() = v and
  va.getTarget() = dst
}

query predicate enclosingBlk(VariableAccess va, GlobalVariable dst, BlockStmt v){
  va.getEnclosingBlock() = v and
  va.getTarget() = dst
}
