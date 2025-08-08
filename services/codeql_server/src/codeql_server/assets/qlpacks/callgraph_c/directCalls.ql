import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

from Function src, Function dst, FunctionCall call
where call.getEnclosingFunction() = src and call.getTarget() = dst
select src.getName() as src_name, src.getLocation() as src_loc, dst.getName() as dst_name,
  dst.getLocation() as dst_loc, call.getLocation() as call_loc
