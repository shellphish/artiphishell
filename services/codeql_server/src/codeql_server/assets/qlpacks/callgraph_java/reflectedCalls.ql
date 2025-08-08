import java
import semmle.code.java.Reflection
import semmle.code.java.dataflow.TaintTracking

// Currently only focusing on invoke calls
predicate isReflexive(Call c) {
  c instanceof NewInstance or
  c instanceof ReflectiveClassIdentifierMethodCall or
  c instanceof ReflectiveGetAnnotationCall or
  c instanceof ReflectiveGetConstructorsCall or
  c instanceof ReflectiveGetFieldCall or
  c instanceof ReflectiveGetMethodCall or
  c instanceof ReflectiveGetMethodsCall
}

predicate isReal(Callable c) {
  c.getLocation().getStartLine() != 0 and
  c.getLocation().getStartColumn() != 0 and
  c.getLocation().getEndLine() != 0 and
  c.getLocation().getEndColumn() != 0
}

// If something got called with NewInstance, then everything affected by this result may call the class of that instance
module ReflectionTracking implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { exists(NewInstance src | source.asExpr() = src) }

  predicate isSink(DataFlow::Node sink) { exists(VarAccess dst | sink.asExpr() = dst) }
}

module ReflectionFlow = TaintTracking::Global<ReflectionTracking>;

// from DataFlow::Node srcNode, DataFlow::Node dstNode, Call c
// where ReflectionFlow::flow(srcNode, dstNode) and c.getQualifier() = dstNode.asExpr().(VarAccess)
// select srcNode.asExpr().(NewInstance).getInferredConstructedType() as cls, c
// Naive solution: everything that has a newInstance call times every invoke call
from Method src, Call invoke, NewInstance n
where
  not isReal(invoke.getCallee()) and
  invoke.getCallee().getName() = "invoke" and
  exists(Class cls |
    cls.getAConstructor() = n.getInferredConstructor() and
    cls.getAMethod() = src
  )
select src, invoke
