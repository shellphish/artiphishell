import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.pointsto.CallGraph

predicate edge(Function src, Function dst){
  allCalls(src,dst)
}

predicate is_source_function(Function f) {
  f.hasGlobalName("[FUNCTION_NAME]")
}

from Function src, Function dst
where
is_source_function(dst) and 
edge+(src, dst) 
select src.getName() as name