/**
 * @name Jenkins: Missing permission check on a form fill web method with credentials lookup
 * @description This is a Stapler web method whose name indicates it provides options for a dropdown list UI element. It does not implement a permission check, but ends up calling 'CredentialsProvider#lookupCredentials'.
 *              This is likely a security vulnerability, enumerating credentials IDs to users with only Overall/Read permission.
 *              A permission check should be added.
 *              See the documentation on form validation at https://www.jenkins.io/doc/developer/security/form-validation/ as well as the specific advice in the Credentials plugin consumer guide at https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc#providing-a-ui-form-element-to-let-a-user-select-credentials
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id jenkins/credentials-fill-without-permission-check
 * @tags security
 *       external/cwe/cwe-862
 */

import java
import jenkins.PermissionCheck
import stapler.WebMethod

class CredentialsLookup extends Method {
    CredentialsLookup() {
        this.getDeclaringType().hasQualifiedName("com.cloudbees.plugins.credentials", "CredentialsProvider") and this.hasName("lookupCredentials")
        or
        this.getDeclaringType().hasQualifiedName("com.cloudbees.plugins.credentials.common", "AbstractIdCredentialsListBoxModel<StandardListBoxModel,StandardCredentials>")
    }
}

class DoFillWebMethod extends WebMethod {
    DoFillWebMethod() {
        this.getName().indexOf("doFill") = 0
    }
}

from DoFillWebMethod m, CredentialsLookup t
where
    m.fromSource() and
    not exists(PermissionCheck c | m.polyCalls*(c)) and
    m.polyCalls+(t)
    // exists ( | m.polyCalls+(t))
select m, m.getName() + " should perform a permission check before calling #" + t.getName()
