import cpp
query predicate enclosingBlk(FunctionAccess fa, Function dst, BlockStmt v){
  fa.getEnclosingBlock() = v and
  fa.getTarget() = dst
}