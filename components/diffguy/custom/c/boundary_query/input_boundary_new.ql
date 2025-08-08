import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

predicate argCountMatch(Call src, Function dst) {
  src.getNumberOfArguments() = dst.getNumberOfParameters()
}

predicate funcCallsFunc(Function a, Function b) {
  exists(Call c |
    c.getEnclosingFunction() = a and
    (
      (
        exists(FunctionAccess fa | fa.getTarget() = b) and
        c instanceof ExprCall and
        argCountMatch(c, b)
      )
      or
      (
        c instanceof FunctionCall and
        c.getTarget() = b
      )
    )
  )
}

from Function src, Function dst
where
  funcCallsFunc+(src, dst) and
  src.getName() = "LLVMFuzzerTestOneInput" and
  (
    dst.getLocation().getFile().getAbsolutePath().matches("%.c") or
    dst.getLocation().getFile().getAbsolutePath().matches("%.cpp")
  )
select src as entryPoint, src.getLocation() as entryPointId, dst as end, dst.getLocation() as endId
