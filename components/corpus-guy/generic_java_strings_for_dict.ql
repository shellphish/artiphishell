/**
 * @id cpp/generic_c_reaching_files_strings
 * @kind problem
 * @name Finds string literals in filepaths involved with reaching a given set of target functions
 * @severity information
 */

import java

from StringLiteral s
where
  s.getValue().length() > 2
  // if the path contains `src/test/` it's not relevant
  and
  not s.getLocation().getFile().getAbsolutePath().matches("%src/test/%")
  and
  not s.getLocation().getFile().getAbsolutePath().matches("%.class")
  // if the string is used in an exception constructor, ignore it
  and
  not exists(ClassInstanceExpr cie |
    cie.getType().getName().matches("%Exception")
    and
    (cie.getAnArgument() = s or cie.getAnArgument().getAChildExpr+() = s)
  )
  and
  // remove common functions like Logger.debug, Logger.info, Logger.error, etc.
  not exists(Call call |
    // first, check if the string is an argument to the call
    (call.getAnArgument() = s or call.getAnArgument().getAChildExpr+() = s)
    and
    // check that the call is to a logging function
    (
      call.getCallee().getName().matches("%debug")
      or
      call.getCallee().getName().matches("%error")
      or
      call.getCallee().getName().matches("%info")
      or
      call.getCallee().getName().matches("%trace")
      or
      call.getCallee().getName().matches("%warn")
    )
    // check that the call is to a logging class
    and
    (
      call.getCallee().getDeclaringType().getName().matches("Logger")
    )
  )
  and 
  // remove strings that are used in exception classes
  not (
    s.getEnclosingCallable().getDeclaringType().getName().matches("%Exception")
  )
  and
  // remove strings that are printed to the console
  not exists(Call call |
    (call.getAnArgument() = s or call.getAnArgument().getAChildExpr+() = s)
    and
    (
      call.getCallee().getName().matches("%print")
      or
      call.getCallee().getName().matches("%println")
    )
    and
    call.getCallee().getDeclaringType().getName().matches("PrintStream")
  )
  and
  // remove String.format calls
  not exists(Call call |
    (call.getAnArgument() = s or call.getAnArgument().getAChildExpr+() = s)
    and
    call.getCallee().getName().matches("%format")
    and
    call.getCallee().getDeclaringType().getName().matches("String")
  )
  and
  // remove literals used in the computation of toString method
  not s.getEnclosingCallable().getName().matches("toString")
select s.getValue(), s.getLocation()