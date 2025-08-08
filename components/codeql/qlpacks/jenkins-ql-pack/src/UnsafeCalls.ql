/**
 * @name Jenkins: Generally unsafe method calls
 * @description Jenkins plugins generally should not call any of these methods.
 *              While there may be legitimate use cases, care needs to be taken that these don't cause problems.
 *              See the documentation on misc APIs: https://www.jenkins.io/doc/developer/security/misc/
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/unsafe-calls
 * @tags security
 */

import java
import jenkins.ProductionCallable

class UnsafeMethod extends Method {
    UnsafeMethod() {
        (this.isStatic() and this.getDeclaringType().hasQualifiedName("java.lang", "System") and this.hasName("exit"))
        or (this.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and this.hasName("exec"))
        or (this.getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") and this.hasName("init"))
        or (this.isStatic() and this.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and this.hasName("setDefaultSSLSocketFactory"))
        or (this.isStatic() and this.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and this.hasName("setDefaultHostnameVerifier"))
        or (this.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and this.hasName("setHostnameVerifier"))
        or (this.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and this.hasName("setSSLSocketFactory"))
    }
}

from ProductionCallable caller, UnsafeMethod callee
where caller.polyCalls(callee)
select caller, "Potentially unsafe invocation of " + callee.getDeclaringType().getName() + "#" + callee.getName()  //, m.getLocation().getFile(), m.getLocation().getStartLine()
