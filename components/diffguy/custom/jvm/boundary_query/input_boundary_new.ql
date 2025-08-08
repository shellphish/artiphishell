import java

query predicate edges(Callable pred, Callable succ) {
  pred.polyCalls(succ)
  and succ.getName() != ""
}

predicate is_source_function(Callable c) {
  c.getQualifiedName().matches("%.fuzzerTestOneInput") or
  exists (Annotation a |
    c.getADeclaredAnnotation() = a and
    a.toString().matches("FuzzTest"))
}

predicate is_dst_in_java_file(Callable c) {
  c.getLocation().getFile().getAbsolutePath().matches("%.java")
}

from Callable src, Callable dst
where
    edges+(src, dst) and
    is_source_function(src) and
    is_dst_in_java_file(dst)
    

select src.getQualifiedName() as entryPoint, src.getLocation() as entryPointId, dst.getQualifiedName() as end, dst.getLocation() as endId