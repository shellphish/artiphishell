import cpp
query predicate enclosingStmt(FunctionAccess fa, Function dst, Stmt v){
  fa.getEnclosingStmt() = v and
  fa.getTarget() = dst
}