/**
 * @id cpp/generic_c_reaching_files_strings
 * @kind problem
 * @name Finds string literals in filepaths involved with reaching a given set of target functions
 * @severity information
 */

import cpp

from StringLiteral s
where
  s.getValue().length() > 2
  // and
  // if the string is used in a `strerror` function that returns error messages, it's probably not input related
  // // not s.getEnclosingFunction().getName().matches("%strerror")
  and 
  // filter out strings that are passed to logging routines
  not exists(FunctionCall call |
    (call.getAnArgument() = s or call.getAnArgument().getAChild() = s)
    and
    (
      call.getTarget().getName().matches("%_log_%")
      or
      call.getTarget().getName().matches("log_%")
      or
      call.getTarget().getName().matches("%_log")
      or
      call.getTarget().getName().matches("%Log%")
      or
      call.getTarget().getName().matches("Log%")
      or
      call.getTarget().getName().matches("%Puts")
      or
      call.getTarget().getName().matches("puts")
      or
      call.getTarget().getName().matches("write")
      or
      call.getTarget().getName().matches("%Printf")
      or
      call.getTarget().getName().matches("_fatal_")
      // or
      // call.getTarget().getName().matches("%_error")
      or 
      call.getTarget().getName().matches("perror")
      or
      call.getTarget().getName().matches("%_set_error")
    )
  )
  // filter out printf, fprintf, etc. calls
  and
  not exists(FormattingFunctionCall call |
    call.getFormat() = s or call.getFormat().getAChild() = s  
  )
  and 
  not exists(FunctionCall call |
    (
      call.getTarget().getName().matches("__printf_chk")
      and
      call.getArgument(1) = s or call.getArgument(1).getAChild() = s
    )
    or
    (
      call.getTarget().getName().matches("__fprintf_chk")
      and
      call.getArgument(2) = s or call.getArgument(2).getAChild() = s
    )
    or
    (
      call.getTarget().getName().matches("__sprintf_chk")
      and
      call.getArgument(3) = s or call.getArgument(3).getAChild() = s
    )
    or
    (
      call.getTarget().getName().matches("__snprintf_chk")
      and
      call.getArgument(4) = s or call.getArgument(4).getAChild() = s
    )
  )
select s.getValue(), s.getLocation()