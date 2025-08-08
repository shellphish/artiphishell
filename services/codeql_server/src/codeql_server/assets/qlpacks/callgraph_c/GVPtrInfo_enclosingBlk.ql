import cpp
query predicate enclosingBlk(VariableAccess va, GlobalVariable dst, BlockStmt v){
  va.getEnclosingBlock() = v and
  va.getTarget() = dst
}