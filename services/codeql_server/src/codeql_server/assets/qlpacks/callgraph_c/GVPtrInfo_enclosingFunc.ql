import cpp
query predicate enclosingFunc(VariableAccess va, GlobalVariable dst, Function v){
  va.getEnclosingFunction() = v and
  va.getTarget() = dst
}