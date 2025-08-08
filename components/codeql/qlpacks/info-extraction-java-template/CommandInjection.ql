/**
 * @id java/CommandInjection
 * @kind problem
 * @name List all function calls in paths related to source and target functions
 * @severity information
 */

import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions

// Base predicate for direct calls
predicate edges(Callable pred, Callable succ) {
  pred.calls(succ) and
  succ.getName() != ""
}

predicate is_target_function(Callable c) { 
  c.getQualifiedName().matches("%.ProcessBuilder") or 
  c instanceof RuntimeExecMethod
}

predicate is_harness_function(Callable c) { 
  c.getQualifiedName().matches("%.fuzzerTestOneInput") 
}

// Helper predicates to cache common computations
predicate source_reachable(Callable c) {
  is_harness_function(c) or
  exists(Callable prev | source_reachable(prev) and edges(prev, c))
}

predicate target_reachable(Callable c) {
  is_target_function(c) or
  exists(Callable next | target_reachable(next) and edges(c, next))
}

from Callable prevcall, Callable inbetween, Callable dest, Call tcall
where
  // Must have a valid call relationship
  prevcall.calls(inbetween) and
  tcall = prevcall.getACallSite(inbetween) and
  
  // At least one of these must be true to be interesting
  (
    source_reachable(prevcall) or
    target_reachable(inbetween) or
    (source_reachable(prevcall) and target_reachable(inbetween))
  )
  and
  is_target_function(dest)

select
  prevcall,
  inbetween,
  tcall.getLocation().getFile().getAbsolutePath(),
  tcall.getLocation().getStartLine(),
  prevcall.getLocation().getFile().getAbsolutePath(),
  prevcall.getLocation().getStartLine(),
  inbetween.getLocation().getFile().getAbsolutePath(),
  inbetween.getLocation().getStartLine(),
  "OS Command Injection",
  dest.getLocation()