import cpp
query predicate enclosingGVar(FunctionAccess fa, Function dst, GlobalVariable v){
  fa.getEnclosingVariable() = v and
  fa.getTarget() = dst
}