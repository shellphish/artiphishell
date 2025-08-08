import cpp

from Function f, ExprCall call, int argIdx
where call.getEnclosingFunction() = f
select f.getLocation() as id, call.getLocation() as cid, argIdx, call.getArgument(argIdx).getType().toString() as arg