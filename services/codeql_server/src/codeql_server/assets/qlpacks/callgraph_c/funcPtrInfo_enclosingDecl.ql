import cpp
query predicate enclosingDecl(FunctionAccess fa, Function dst, Declaration v){
  fa.getEnclosingDeclaration() = v and
  fa.getTarget() = dst
}