/**
 * @id jenkins/aixcc-exemplar
 * @kind problem
 * @name find path from harness to arbitrary code execution
 * @severity information
 */

import java

query predicate edges(Callable pred, Callable succ) {
pred.polyCalls(succ)
and succ.getName() != ""
}

// This gonna take forever to run, please optimize

from Callable inbetween
where
exists(Callable src, Callable dest |
    src.getQualifiedName().matches("%.fuzzerTestOneInput") and
    dest.getQualifiedName().matches("%.ProcessBuilder.start") and
    edges+(src, inbetween) and
    edges+(inbetween, dest)
)
select inbetween.getQualifiedName(), inbetween.getLocation()
