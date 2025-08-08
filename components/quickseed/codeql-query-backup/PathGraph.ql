/**
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class TypeObjectInputStream extends RefType {
  TypeObjectInputStream() {
    //this.hasQualifiedName("java.io", "ObjectInputStream")
    this.hasQualifiedName("java.lang", "ProcessBuilder")
  }
}

module ObjectInputStreamConfig implements DataFlow::ConfigSig {

  /*
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }
  */


  predicate isSource(DataFlow::Node source) {
    exists(Method f |
      //f.getDeclaringType().hasQualifiedName("io.jenkins.plugins.UtilPlug", "UtilMain") and 
      f.getName() = "doexecCommandUtils" and   
      f.getAParameter() = source.asParameter() )
  
  }


  predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType() instanceof TypeObjectInputStream and
      sink.asExpr() = ma.getQualifier()
    )
  }
}


module myFlow = TaintTracking::Global<ObjectInputStreamConfig>;
//import myFlow::PathGraph
query predicate edges(myFlow::PathNode a, myFlow::PathNode b, string key, string val, string filepath_a, string filepath_b, int line_a, int line_b, string call_a, string call_b){
myFlow::PathGraph::edges(a, b, key, val) and
//loc_a = a.getNode().getLocation() and
//loc_b = b.getNode().getLocation()
filepath_a = a.getNode().getLocation().getFile().getAbsolutePath() and
filepath_b = b.getNode().getLocation().getFile().getAbsolutePath() and
line_a = a.getNode().getLocation().getStartLine() and
line_b = b.getNode().getLocation().getStartLine() and 
call_a = a.getNode().getEnclosingCallable().getName() and
call_b = b.getNode().getEnclosingCallable().getName()
}
from DataFlow::Node source, DataFlow::Node sink
where myFlow::flow(source, sink)
select source, 
sink, 
"OS Command Injection", 
 source.getLocation().getFile().getAbsolutePath(), // Source file path
  source.getLocation().getStartLine(), // Source start line
  source.getEnclosingCallable().getName(),
  //source.getEnclosingCallable().getDeclaringType().getName(),
sink.getLocation().getFile().getAbsolutePath(), // Sink file path
  sink.getLocation().getStartLine(), // Sink start line
  sink.getEnclosingCallable().getName()
