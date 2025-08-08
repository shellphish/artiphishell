This web method retrieves a list of credentials IDs without performing a permission check, potentially displaying them to the user.

## Why is this a problem?

Knowledge of credentials IDs in Jenkins can help attackers retrieve credentials. While it's impossible to hide them entirely, lists should be returned only to authorized users.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/credentials-fill-without-permission-check]")` or add this comment just before: `// lgtm[jenkins/credentials-fill-without-permission-check]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

Make sure the code does all of the following:

1. It looks up credentials and retrieves a list, e.g. using `CredentialsProvider#lookupCredentials`.
2. This list of credentials, or a part of is, is returned form the method, e.g. in a `StandardListBoxModel`.
3. No permission checks are performed.

## How can I fix the code?

Add a permission check as documented in the [consumer guide of the Credentials plugin](https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc#providing-a-ui-form-element-to-let-a-user-select-credentials).
