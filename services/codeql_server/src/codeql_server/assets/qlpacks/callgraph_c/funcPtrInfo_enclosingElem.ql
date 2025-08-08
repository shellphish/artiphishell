import cpp
query predicate enclosingElem(FunctionAccess fa, Function dst, Element v){
  fa.getEnclosingElement() = v and
  fa.getTarget() = dst
}