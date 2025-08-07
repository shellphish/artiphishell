/**
 * @name Jenkins: Plaintext password storage
 * @description A Jenkins component class that may store a password, token, or similar credentials in plain text when serialized.
 *              See the documentation on storing secrets in Jenkins: https://www.jenkins.io/doc/developer/security/secrets/
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/plaintext-storage
 * @tags security
 *       external/cwe/cwe-256
 *       external/cwe/cwe-312
 */

import java

class StringField extends Field {
    StringField() {
        this.getType().getName() = "String" and not this.getAModifier().hasName("transient") and not this.isStatic()
    }

    predicate isProduction() {
        this.getCompilationUnit().getAbsolutePath().indexOf("src/main/java") != -1
        or // support QL test sources
        this.getCompilationUnit().getAbsolutePath().indexOf("test/query-tests") != -1
    }
}

class StringCredentialField extends StringField {
    StringCredentialField() {
        (this.getName().toLowerCase().indexOf("password") != -1
        or this.getName().toLowerCase().indexOf("pwd") != -1
        or this.getName().toLowerCase().indexOf("pass") != -1
        or this.getName().toLowerCase().indexOf("credential") != -1
        or this.getName().toLowerCase().indexOf("access") != -1
        or this.getName().toLowerCase().indexOf("key") != -1
        or this.getName().toLowerCase().indexOf("token") != -1)
        and not (this.getName().toLowerCase().indexOf("credentialsid") != -1)
        and not (this.getName().toLowerCase().indexOf("credentialid") != -1)
    }
}

from StringCredentialField m
where m.fromSource() and m.isProduction()
select m, "Field should be reviewed whether it stores a password and is serialized to disk: " + m.getName()
