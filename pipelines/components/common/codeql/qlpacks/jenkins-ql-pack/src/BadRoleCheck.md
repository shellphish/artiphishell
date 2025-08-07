This `Callable` implements `#checkRoles(RoleChecker)` without calling `RoleChecker#check` on the provided argument.

## Why is this a problem?

This code may allow agent processes to execute code on the Jenkins controller. As a result it could compromise security on Jenkins before 2.319 and LTS 2.303.3.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/callable-without-role-check]")` or add this comment just before: `// lgtm[jenkins/callable-without-role-check]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

While some Callables are intended to be sent in the agent-to-controller direction, [a security hardening in Jenkins 2.319 and LTS 2.303.3](https://www.jenkins.io/doc/book/security/controller-isolation/required-role-check/) rejects any Callables sent in the agent-to-controller direction if there's an empty role check. As a result, your users would probably already have reported a regression when using recent versions of Jenkins.

It is possible that you're using the `Callable` interface for code that is only ever invoked locally rather than through a remoting channel _and_ your implementation has fields that cannot be serialized. In that case, this finding would not be a real concern, but it's still recommended that you switch to `NotReallyRoleSensitiveCallable` to make your intention clear.

## How can I fix the code?

If the `Callable` is always invoked locally, it should extend `NotReallyRoleSensitiveCallable` and stop overriding `#checkRoles`.

If the `Callable` is potentially sent from the controller to agents, it should extend `MasterToSlaveCallable` and stop overriding `#checkRoles`.

In very rare cases, the `Callable` needs to be sent from an agent to the controller. More work is needed to ensure this is done safely. See the [developer guide for remoting callables](https://www.jenkins.io/doc/developer/security/remoting-callables/) for more information.
