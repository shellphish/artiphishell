/**
 * @name Jenkins: Potentially unsafe classes
 * @description Use of these classes is potentially unsafe, usually due to bad defaults or inherent issues invoking these with user data.
 *              Care needs to be taken that these don't cause problems.
 *              See the documentation on misc APIs use in Jenkins: https://www.jenkins.io/doc/developer/security/misc/
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id jenkins/unsafe-classes
 * @tags security
 */

import java
import jenkins.ProductionCallable

class UnsafeClass extends Class {
    UnsafeClass() {
        this.hasQualifiedName("groovy.lang", "GroovyShell")
        or this.hasQualifiedName("groovy.text", "GStringTemplateEngine")
        or this.hasQualifiedName("groovy.text", "SimpleTemplateEngine")
        or this.hasQualifiedName("groovy.text", "StreamingTemplateEngine")
        or this.hasQualifiedName("groovy.text", "TemplateEngine")
        or this.hasQualifiedName("groovy.text", "XmlTemplateEngine")
        or this.hasQualifiedName("groovy.util", "GroovyScriptEngine")
        or this.hasQualifiedName("hudson", "ExpressionFactory2")
        or this.hasQualifiedName("hudson.util.spring", "BeanBuilder")
        or this.hasQualifiedName("javaposse.jobdsl.dsl", "DslScriptLoader")
        or this.hasQualifiedName("javax.script", "ScriptEngineManager")
        or this.hasQualifiedName("javax.xml.transform", "TransformerFactory")
        or this.hasQualifiedName("org.apache.commons.digester", "Digester")
        or this.hasQualifiedName("org.apache.commons.digester3", "Digester")
        or this.hasQualifiedName("hudson.util", "Digester2")
        or this.hasQualifiedName("org.apache.commons.jelly", "GroovyShell")
        or this.hasQualifiedName("org.apache.commons.jelly", "Script")
    }
}

from ProductionCallable caller, UnsafeClass u
where caller.polyCalls(u.getACallable())
select caller, "This use of class $@ should be reviewed for unsafe behavior, like allowing XML External Entity injection, or arbitrary code execution.", u, u.getQualifiedName()
