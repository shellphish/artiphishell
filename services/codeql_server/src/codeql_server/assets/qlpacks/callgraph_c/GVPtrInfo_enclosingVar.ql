import cpp
query predicate enclosingVar(VariableAccess va, GlobalVariable dst, Variable v){
  va.getEnclosingVariable() = v and
  va.getTarget() = dst
}