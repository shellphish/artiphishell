This Stapler web method does not perform a permission check.

## Why is this a problem?

This is problem if the method returns private information, or has side effects, as anyone with only basic access to Jenkins can access the web method directly.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/no-permission-check]")` or add this comment just before: `// lgtm[jenkins/no-permission-check]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

This check can easily identify _false positives_, i.e. safe code that is marked as being unsafe, for any of the following reasons:

1. The information being returned is not private.
2. The method does not have side effects.
3. The method is otherwise protected.
4. The method is not actually routable.

### What is private information?

Anything a user would not usually be entitled to have access to without additional permissions:

1. Information about the configuration of the system usually requires Overall/Manage, Overall/SystemRead, or Overall/Administer permission.
2. Information about the configuration of a job usually requires Job/Configure or Job/ExtendedRead permission (although some information will be displayed to users with Job/Read permission -- and that information does not need further permission to access).

As a rule of thumb, if a user with a given level of access can obtain the information through an intended UI or API, it's not a problem. It's also not a problem if a user could obtain the same information by reading the source code of the plugin (e.g. `doFill` methods providing a fixed list of combobox options). It's only a problem when direct browsing to URLs would reveal information they would not otherwise be able to access.

### What are side effects?

Side effects for the purpose of this check are any of of the following:

1. Changing system state (e.g. a URL handling form submissions will change some configuration).
2. Connecting to other services, e.g. by sending HTTP requests. A notable exception to this is plugins integrating with [Credentials Plugin](https://plugins.jenkins.io/credentials/): While a permission check _is_ needed (see [the Credentials Plugin consumer guide](https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc#providing-a-ui-form-element-to-let-a-user-select-credentials)), it's because enumerating credentials is restricted to users with the appropriate permissions, rather than the potential side effect of accessing [`CredentialsProvider`](https://www.jenkins.io/doc/developer/extensions/credentials/#credentialsprovider) over the network.
3. Expensive computations, especially if the cost is depending on user input.

### Other methods of protection

Stapler request routing does not require that each individual web method perform a permission check. A common solution, if entire objects are intended to be protected from lower-privilege users, is to implement `StaplerProxy` and use the `#getTarget` method to implement a permission check, returning `this` when it is successful.

An example of this is [`AdministrativeMonitor`](https://github.com/jenkinsci/jenkins/blob/39fd38fd86d7e7cb0a13e32562d36d67ff52a5f9/core/src/main/java/hudson/model/AdministrativeMonitor.java#L198-L210), which is always only accessible to users with the specified permission. Individual web methods of this class or its subclasses do not need to have separate permission checks (unless additional permissions are required for some of them).

Besides this limitation, this check has a known bug: It currently does not identify calls to `AccessControlled#checkAnyPermission` or `AccessControlled#hasAnyPermission` as implementing a permission check.

### Non-routable methods

This check identifies methods matching the Stapler web method naming scheme (e.g. `doWhatever`) even if they have no arguments and declare a `void` return type. [Since Jenkins 2.154 and LTS 2.138.4, these methods can no longer be invoked by Stapler](https://www.jenkins.io/doc/developer/handling-requests/actions/), so do not need a permission check.

## How can I fix the code?

You generally want to add a permission check to the method. Broadly speaking, there are two strategies:

Calling `#checkPermission` will throw an exception if the current user does not have the specified permission:
```java
Jenkins.get().checkPermission(Jenkins.ADMINISTER)
```
Calling `#hasPermission` will return whether the current user has the specified permission and can be used to customize the response, like a form validation not performing actions with side effects:
```java
public FormValidation doCheckUrl(@QueryParameter String value) {
    if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
        return FormValidation.ok();
    }
    // Ensure 'value' is a valid URL actually pointing to the service being configured
}
```
For further information, see [the documentation on safely implementing form validation](https://www.jenkins.io/doc/developer/security/form-validation/). Despite the name, it applies to more than just form validation.
