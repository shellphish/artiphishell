import java

query predicate edges(Method caller, Method callee) {
  caller.polyCalls(callee) and
  caller.getCompilationUnit().fromSource() and
  callee.getCompilationUnit().fromSource() and
  not caller.hasName("<clinit>") and
  not callee.hasName("<clinit>") and
  isNotTest(caller) and
  isNotTest(callee) and
  caller.getName() != "" and
  callee.getName() != "" and
//  not caller instanceof Constructor and
//  not callee instanceof Constructor and
  not caller.getDeclaringType() instanceof Interface and
  not callee.getDeclaringType() instanceof Interface
}

query predicate isNotTest(Callable callable) {
  not callable.getDeclaringType() instanceof TestClass or
  callable.getDeclaringType().getQualifiedName().matches("com.code_intelligence.jazzer.%")
}


// Select paths from source to target
from Method target, Method source
where edges(source, target) // The + indicates one or more applications of the edges predicate
select 
    source.getName() as src_name,
    target.getName() as dst_name,
    source.getLocation() as src_loc,
    target.getLocation() as dst_loc
    // source.getLocation().getStartLine() as source_lineno,
    // target.getLocation().getStartLine() as target_lineno
