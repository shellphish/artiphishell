import cpp
query predicate enclosingGVar(VariableAccess va, GlobalVariable dst, GlobalVariable v){
  va.getEnclosingVariable() = v and
  va.getTarget() = dst
}