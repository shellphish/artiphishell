This method uses one of several classes considered dangerous if used incorrectly.

## Why is this a problem?

Incorrect use of APIs can result in a security vulnerability.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/unsafe-classes]")` or add this comment just before: `// lgtm[jenkins/unsafe-classes]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

This check can easily identify _false positives_, i.e. safe code that is marked as being unsafe.

Determine which of the listed classes are used by your code and review the argument for why this check detects them. If the problem being described does not apply to your code, you can ignore this finding.

### Scripting APIs

Using these scripting-related classes with user-controlled input is generally unsafe, unless steps have been taken to prevent arbitrary remote code execution:

* `groovy.lang.GroovyShell`
* `groovy.text.GStringTemplateEngine`
* `groovy.text.SimpleTemplateEngine`
* `groovy.text.StreamingTemplateEngine`
* `groovy.text.TemplateEngine`
* `groovy.text.XmlTemplateEngine`
* `groovy.util.GroovyScriptEngine`
* `hudson.ExpressionFactory2`
* `hudson.util.spring.BeanBuilder`
* `javaposse.jobdsl.dsl.DslScriptLoader`
* `javax.script.ScriptEngineManager`
* `org.apache.commons.jelly.GroovyShell`
* `org.apache.commons.jelly.Script`

### XML processing

XML processing using the following classes can easily result in XXE vulnerabilities [unless steps have been taken to prevent them](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html):

* `hudson.util.Digester2`
* `javax.xml.transform.TransformerFactory`
* `org.apache.commons.digester.Digester`
* `org.apache.commons.digester3.Digester`

## How can I fix the code?

See the [documentation on misc APIs](https://www.jenkins.io/doc/developer/security/misc/) for recommendations.
