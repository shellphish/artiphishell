import cpp
query predicate enclosingFunc(FunctionAccess fa, Function dst, Function v){
  fa.getEnclosingFunction() = v and
  fa.getTarget() = dst
}