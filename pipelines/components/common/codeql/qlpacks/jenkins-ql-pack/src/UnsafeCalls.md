This method invokes one of several methods considered dangerous if used incorrectly.

## Why is this a problem?

Incorrect use of APIs can result in a security vulnerability.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/unsafe-calls]")` or add this comment just before: `// lgtm[jenkins/unsafe-calls]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

This check can easily identify _false positives_, i.e. safe code that is marked as being unsafe.

Determine which of the listed methods are invoked by your code and review the argument for why this check detects them. If the problem being described does not apply to your code, you can ignore this finding.

### SSL/TLS related APIs

The following methods should never be called in a plugin to weaken SSL/TLS protection, as they will change the SSL/TLS handling for the entire JVM:

* `javax.net.ssl.HttpsURLConnection#setDefaultSSLSocketFactory`
* `javax.net.ssl.HttpsURLConnection#setDefaultHostnameVerifier`

The following methods should only be called after an appropriate user (usually Job/Configure or Overall/Administer permission, depending on context) has opted to ignore SSL/TLS problems.

* `javax.net.ssl.SSLContext#init`
* `javax.net.ssl.HttpsURLConnection#setHostnameVerifier`
* `javax.net.ssl.HttpsURLConnection#setSSLSocketFactory`

### Other APIs

* `java.lang.System#exit` should generally not be called in Jenkins plugin code, as the entire (controller or agent) process will be stopped.
* `java.lang.Runtime#exec` should not be called from build steps and similar contexts that execute on the controller, especially if some or all of the arguments are provided by users with limited permissions to access Jenkins. If this code is executed during a build, look into [`hudson.Launcher`](https://javadoc.jenkins.io/hudson/Launcher.html) and [distributed builds](https://www.jenkins.io/doc/developer/distributed-builds/).

## How can I fix the code?

See the [documentation on misc APIs](https://www.jenkins.io/doc/developer/security/misc/) for recommendations.
