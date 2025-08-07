This Stapler web method is not protected from [cross-site request forgery](https://owasp.org/www-community/attacks/csrf) (CSRF).

## Why is this a problem?

This is problem if the method has side effects, as legitimate Jenkins users' browsers could be tricked into accessing this web method from another website.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/csrf]")` or add this comment just before: `// lgtm[jenkins/csrf]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

This check can easily identify _false positives_, i.e. safe code that is marked as being unsafe, for any of the following reasons:

1. The method does not have side effects.
2. The method is not actually routable.
3. The method has an implicit protection from CSRF

### What are side effects?

Side effects for the purpose of this check are any of of the following:

1. Changing system state (e.g. a URL handling form submissions will change some configuration).
2. Connecting to other services, e.g. by sending HTTP requests. A notable exception to this is plugins integrating with [Credentials Plugin](https://plugins.jenkins.io/credentials/): While a permission check _is_ needed (see [the Credentials Plugin consumer guide](https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc#providing-a-ui-form-element-to-let-a-user-select-credentials)), it's because enumerating credentials is restricted to users with the appropriate permissions, rather than the potential side effect of accessing [`CredentialsProvider`](https://www.jenkins.io/doc/developer/extensions/credentials/#credentialsprovider) over the network.
3. Expensive computations, especially if the cost is depending on user input.

### Non-routable methods

This check identifies methods matching the Stapler web method naming scheme (e.g. `doWhatever`) even if they have no arguments and declare a `void` return type. [Since Jenkins 2.154 and LTS 2.138.4, these methods can no longer be invoked by Stapler](https://www.jenkins.io/doc/developer/handling-requests/actions/), so do not need a permission check.

### Implicit CSRF protection

Jenkins 2.287 and newer, LTS 2.277.2 and newer prevent exploitation of CSRF vulnerabilities if the code calls `StaplerRequest#getSubmittedForm`, expecting to process a form submission. If this plugin is only compatible with Jenkins releases newer than this, no explicit CSRF protection needs to be added. It is still recommended so that the code is more obviously safe.

## How can I fix the code?

You should generally add either the `@RequirePOST` or `@POST` annotations to this method:

* Use `@RequirePOST` for a simple action that advanced users may conceivably navigate to directly. An example of that would be `ParameterizedJobMixIn.ParameterizedJob#doDisable` providing the URL `/job/(name)/disable`. Instead of an error message, the user will be shown a form to confirm the action.
* Use `@POST` for anything expecting a real form submission (e.g. various methods called `#doConfigSubmit` by convention) or not intended to be used directly.

Other HTTP verb annotations besides `@POST` exist, but these support APIs and are generally not a simple fix for this finding.

For further information, see [the documentation on safely implementing form validation](https://www.jenkins.io/doc/developer/security/form-validation/). Despite the name, it applies to more than just form validation.
