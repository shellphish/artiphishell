import cpp
query predicate enclosingVar(FunctionAccess fa, Function dst, Variable v){
  fa.getEnclosingVariable() = v and
  fa.getTarget() = dst
}