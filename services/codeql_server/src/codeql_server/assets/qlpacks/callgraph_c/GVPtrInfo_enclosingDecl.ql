import cpp
query predicate enclosingDecl(VariableAccess va, GlobalVariable dst, Declaration v){
  va.getEnclosingDeclaration() = v and
  va.getTarget() = dst
}