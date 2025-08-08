import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

predicate calls(Call src, Function dst) {
  exists(FunctionAccess fa | fa.getTarget() = dst) and src instanceof ExprCall
  or
  src.(FunctionCall).getTarget() = dst
}

predicate argCountMatch(Call src, Function dst) {
  src.getNumberOfArguments() = dst.getNumberOfParameters()
}

predicate argTypeMatch(Call src, Function dst) {
  not exists(int i | src.getArgument(i).getType() != dst.getParameter(i).getType())
}

predicate funcCallsFunc(Function a, Function b) {
  exists(Call c |
    c.getEnclosingFunction() = a and calls(c, b) and argCountMatch(c, b)
  )
}


from Function src, Function mid, Function dst
where
  funcCallsFunc+(src, dst) and
  dst.getName() = "[FUNCTION_NAME]"
select src.getName() as name