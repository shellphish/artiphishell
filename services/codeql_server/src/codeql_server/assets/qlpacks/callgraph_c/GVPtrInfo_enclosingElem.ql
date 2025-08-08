import cpp
query predicate enclosingElem(VariableAccess va, GlobalVariable dst, Element v){
  va.getEnclosingElement() = v and
  va.getTarget() = dst
}