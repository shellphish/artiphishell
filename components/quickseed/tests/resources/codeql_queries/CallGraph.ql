import java

query predicate edges(Callable caller, Callable callee) {
  caller.polyCalls(callee)
}

// Select paths from source to target
from Callable target, Callable source
where edges+(source, target) // The + indicates one or more applications of the edges predicate
select 
    source.getQualifiedName() as source_qualified_name,
    target.getQualifiedName() as target_qualified_name,
    source.getLocation().getFile().getAbsolutePath() as source_filepath,
    target.getLocation().getFile().getAbsolutePath() as target_filepath,
    source.getLocation().getStartLine() as source_lineno,
    target.getLocation().getStartLine() as target_lineno