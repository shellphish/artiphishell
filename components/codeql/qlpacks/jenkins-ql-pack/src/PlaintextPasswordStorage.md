This may be a field storing a password, token, or similar credential as part of configuration.

## Why is this a problem?

Jenkins stores lots of credentials to other systems, like agent cloud providers, SCMs, or artifact repositories. To prevent unauthorized users from obtaining these credentials, they should never be stored unencrypted in the configuration.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/plaintext-storage]")` or add this comment just before: `// lgtm[jenkins/plaintext-storage]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

This finding is based entirely on the _name_ and _type_ of the field. It does not confirm that instances of this class are serialized to disk, e.g. as part of Jenkins XML files. So you need to check whether that's the case.

Some examples where your information may be stored:

* The global `config.xml` file stores some configuration, like security realms (LDAP, Active Directory, GitLab, etc.).
* Individual `Descriptor` XML files store configuration related to the `Descriptor` and usually have names corresponding to the fully-qualified class name.
* `config.xml` files for agents or items (like folders or jobs) stores the configuration of these entities.
* `build.xml` files store build-related information, including any `Action` attached to it.

## How can I fix the code?

The easiest solution is generally to switch to the `Secret` type. It can automatically load unencrypted configuration, and it stored encrypted.

If this is the configuration of a build step, and it is Pipeline-compatible, consider making your plugin look up a credential using [Credentials plugin](https://plugins.jenkins.io/credentials/) instead of storing a password directly, so that only a `credentialsId` would need to be stored in the pipeline. This will also make it easier for Jenkins admins to change passwords without updating dozens or hundreds of jobs. See the [Credentials plugin consumer guide](https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc) to learn how to use it with your plugin.
