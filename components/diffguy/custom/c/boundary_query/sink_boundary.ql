import cpp

class TargetMethod extends Function  {
  TargetMethod() {
    this.getQualifiedName() = "[FUNCTION_NAME]"
  }
}

query predicate edges(Function a, Function b) {
  a.calls(b)
}

from TargetMethod end, Function entryPoint
where edges+(entryPoint, end)
select entryPoint, entryPoint.getLocation() as entryPointId, end, end.getLocation() as endId