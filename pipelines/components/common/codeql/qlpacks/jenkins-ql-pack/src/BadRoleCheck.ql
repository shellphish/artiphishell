/**
 * @name Remoting: Unsafe Callable
 * @description A Callable implements #checkRoles(RoleChecker) without calling RoleChecker#check.
 *              This may allow malicious agent processes to execute code on the Jenkins controller, compromising security.
 *              See the method Javadoc: https://javadoc.jenkins.io/component/remoting/org/jenkinsci/remoting/RoleSensitive.html
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/callable-without-role-check
 * @tags security
 *       external/cwe/cwe-693
 */

import java
import jenkins.ProductionCallable

class RoleChecker extends Class {
    RoleChecker() { this.hasQualifiedName("org.jenkinsci.remoting", "RoleChecker") }
}

class RoleCheckerCheckMethod extends Method { // Not a ProductionCallable because it's in library code
    RoleCheckerCheckMethod() {
        this.isPublic()
        and getDeclaringType() instanceof RoleChecker
        and this.hasName("check")
        // TODO check argument types here too
    }
}

class CallableCheckRolesMethod extends Method, ProductionCallable {
    CallableCheckRolesMethod() {
        this.isPublic()
        // and getDeclaringType() instanceof RemotingCallable
        and this.hasName("checkRoles")
        and this.getNumberOfParameters() = 1
        and exists(Parameter p | this.getAParameter() = p
            and p.getType() instanceof RoleChecker
        )
    }
}

from CallableCheckRolesMethod m
where
    not exists(RoleCheckerCheckMethod c | m.polyCalls*(c))
select m, "Potentially unsafe Callable implementation " + m.getDeclaringType().getName() + "#" + m.getName()
