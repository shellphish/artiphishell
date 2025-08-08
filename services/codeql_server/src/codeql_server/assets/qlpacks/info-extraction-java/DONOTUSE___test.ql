/**
 * @id cpp/generic_c_reaching_files_strings
 * @kind problem
 * @name Finds string literals in filepaths involved with reaching a given set of target functions
 * @severity information
 */

import java

// from Call fc
// where
//   // in file named pstops.c
//   fc.getLocation().getFile().getStem() = "UByte"
//   and
//   // line number 1353
//   fc.getLocation().getStartLine() = 197

// select fc, fc.getPrimaryQlClasses(), fc.getCallee(), fc.getCallee().getDeclaringType(), fc.getCallee().getQualifiedName(), fc.getCallee().getDeclaringType().getQualifiedName()


// from StringLiteral s
// where
//   // in file named pstops.c
//   s.getLocation().getFile().getStem() = "WriteLimitReachedException"
//   and
//   // line number 1353
//   s.getLocation().getStartLine() = 33

// select s, s.getPrimaryQlClasses(), s.getEnclosingCallable().getDeclaringType().getName(), s.getEnclosingCallable().getName()




//// ClassInstanceExpr cie |
////   cie.getType().getName().matches("%Exception")
////   and
////   cie.getAnArgument() = s

from ClassInstanceExpr cie
where
  // in file named pstops.c
  cie.getLocation().getFile().getStem() = "OneNotePtr"
  and
  // line number 1353
  cie.getLocation().getStartLine() = 623
  
  
select cie.getType().getName(), cie.getAnArgument(), cie.getAnArgument().getPrimaryQlClasses(), cie.getAnArgument().getAChildExpr+(), cie.getAnArgument().getAChildExpr+().getPrimaryQlClasses()