import cpp
// Do not use: risk of OOM

query predicate enclosingVar(FunctionAccess fa, Function dst, Variable v){
  fa.getEnclosingVariable() = v and
  fa.getTarget() = dst
}

query predicate enclosingGVar(FunctionAccess fa, Function dst, GlobalVariable v){
  fa.getEnclosingVariable() = v and
  fa.getTarget() = dst
}

query predicate enclosingFunc(FunctionAccess fa, Function dst, Function v){
  fa.getEnclosingFunction() = v and
  fa.getTarget() = dst
}

query predicate enclosingElem(FunctionAccess fa, Function dst, Element v){
  fa.getEnclosingElement() = v and
  fa.getTarget() = dst
}

query predicate enclosingStmt(FunctionAccess fa, Function dst, Stmt v){
  fa.getEnclosingStmt() = v and
  fa.getTarget() = dst
}

query predicate enclosingDecl(FunctionAccess fa, Function dst, Declaration v){
  fa.getEnclosingDeclaration() = v and
  fa.getTarget() = dst
}

query predicate enclosingBlk(FunctionAccess fa, Function dst, BlockStmt v){
  fa.getEnclosingBlock() = v and
  fa.getTarget() = dst
}
