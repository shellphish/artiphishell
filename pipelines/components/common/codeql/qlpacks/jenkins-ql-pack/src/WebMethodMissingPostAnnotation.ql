/**
 * @name Stapler: Missing POST/RequirePOST annotation
 * @description This Stapler web method has no verb annotation.
 *              This can be problem if the method has side effects and if so, is known as a CSRF vulnerability.
 *              See the documentation: https://www.jenkins.io/doc/developer/security/form-validation/
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/csrf
 * @tags security
 *       external/cwe/cwe-352
 */

import java
import jenkins.NonTrivialInvocation
import stapler.WebMethod

class AnyVerbAnnotation extends Annotation {
  AnyVerbAnnotation() {
      this.getType().getPackage().hasName("org.kohsuke.stapler.verb")
  }
}

class RequirePostAnnotation extends Annotation {
  RequirePostAnnotation() {
      this.getType().hasQualifiedName("org.kohsuke.stapler.interceptor", "RequirePOST")
  }
}

from NonTrivialInvocation m, WebMethod w
where
  w.polyCalls(m) and
  not(w.getAnAnnotation() instanceof RequirePostAnnotation) and
  not(w.getAnAnnotation() instanceof AnyVerbAnnotation)
select w, "Potential CSRF vulnerability: If " + w.getDeclaringType().getName() + "#" + w.getName() + " connects to user-specified URLs, modifies state, or is expensive to run, it should be annotated with @POST or @RequirePOST"
