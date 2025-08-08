/**
 * @id cpp/generic_c_reaching_files_strings
 * @kind problem
 * @name Finds string literals in filepaths involved with reaching a given set of target functions
 * @severity information
 */

import cpp

from FunctionCall fc
where
  // in file named pstops.c
  fc.getLocation().getFile().getShortName() = "dest"
  and
  // line number 1353
  fc.getLocation().getStartLine() = 2093

select fc, fc.getPrimaryQlClasses()