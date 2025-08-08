import cpp
query predicate enclosingStmt(VariableAccess va, GlobalVariable dst, Stmt v){
  va.getEnclosingStmt() = v and
  va.getTarget() = dst
}