/**
 * @name Use of StaplerRequest#getRestOfPath to construct a file path
 * @description #getRestOfPath and/or the file path resulting from its use needs to be carefully sanitized to not result in a path traversal vulnerability.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/file-from-rest-of-path
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-73
 */

import java
import semmle.code.java.dataflow.TaintTracking

class RestOfPathSource extends DataFlow::ExprNode {
    RestOfPathSource() {
        exists(Method m | m = this.asExpr().(MethodAccess).getMethod() |
            m.hasName("getRestOfPath")
            //and m.getDeclaringType() instanceof TBD
        )
    }
}

class FileSink extends DataFlow::ExprNode {
  FileSink() {
    exists(Constructor c, ConstructorCall cc | cc.getConstructor() = c |
      cc.getAnArgument() = this.getExpr() and c.getDeclaringType().hasQualifiedName("java.io", "File")
    )
  }
}

class RestOfPathToFileConfiguration extends TaintTracking::Configuration {
  RestOfPathToFileConfiguration() { this = "RestOfPathToFileConfiguration" }
  override predicate isSource(DataFlow::Node source) { source instanceof RestOfPathSource }
  override predicate isSink(DataFlow::Node sink) { sink instanceof FileSink }
}

from DataFlow::Node source, DataFlow::Node sink, RestOfPathToFileConfiguration config
where config.hasFlow(source, sink)
select  source, "A file is created from #getRestOfPath, potential path traversal vulnerability $@.", sink, "here"
