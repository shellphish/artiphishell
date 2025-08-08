import cpp

class StartMethod extends Function  {
  StartMethod() {
    this.getQualifiedName() = "LLVMFuzzerTestOneInput"
  }
}

query predicate edges(Function a, Function b) {
  a.calls(b)
}

from  StartMethod entryPoint, Function end
where edges+(entryPoint, end)
select entryPoint, entryPoint.getLocation() as entryPointId, end, end.getLocation() as endId