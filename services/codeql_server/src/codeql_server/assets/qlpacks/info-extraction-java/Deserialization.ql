/**
 * @id java/Deserialization
 * @kind problem
 * @name List all the functions that's in between the harness function and the target function
 * @severity information
 */

import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions

query predicate edges(Callable pred, Callable succ) {
  pred.calls(succ) and
  succ.getName() != ""
}

// query predicate egde_length(Callable pred, Callable succ) {
// }
predicate is_target_function(Callable c) { 
c.getQualifiedName().matches("%.ObjectionInputStream") or
c.getQualifiedName().matches("%.readObject") or
c.getQualifiedName().matches("%.readObjectOverride") or
c.getQualifiedName().matches("%.readUnshared")
}

predicate is_harness_function(Callable c) { c.getQualifiedName().matches("%.fuzzerTestOneInput") }

from Callable src, Callable dest, Callable inbetween, Callable prevcall, Call tcall, Call dcall
where
  is_target_function(dest) and
  is_harness_function(src) and
  edges+(src, inbetween) and
  (
    edges+(src, prevcall) and
    edges+(prevcall, dest)
    or
    prevcall = src
)
  and
   (inbetween = dest or
  edges+(inbetween, dest)
)
  and
  prevcall.calls(inbetween) and
  //inbetween.getCompilationUnit().fromSource() and
        tcall = prevcall.getACallSite(inbetween) and
        tcall.getCaller() = prevcall
select 
prevcall, 
inbetween, 
tcall.getLocation().getFile().getAbsolutePath(), 
tcall.getLocation().getStartLine(), 
prevcall.getLocation().getFile().getAbsolutePath(), 
prevcall.getLocation().getStartLine(), 
inbetween.getLocation().getFile().getAbsolutePath(), 
inbetween.getLocation().getStartLine(), 
"Deserialization", 
dest.getLocation()
