The value from `#getRestOfPath` is used to build a `File`, resulting in a potential path traversal vulnerability.

## Why is this a problem?

If your code is modifying or reading a file as specified in the URL, users able to access this URL may be able to access files outside your intended root directory unless you're restricting allowed values.

## Next Steps

<!-- Generic section used in all findings -->

1. Don't panic, even if this issue is present in previous plugin releases. Do not change your code without understanding why the finding appears. You may end up not fixing the problem, only hiding it instead.
2. Determine whether this finding is a false positive (see guidance below). This is an automated scan result, so that's always a possibility. In general, the rules err on the side of caution, so false positives are pretty common. If it is a false positive, do either of the following, and you're done!
    * [Mark it as such on the GitHub UI](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/managing-code-scanning-alerts-for-your-repository#dismissing--alerts)
    * Suppress the finding through a simple code change: Either annotate the code location with `@SuppressWarnings("lgtm[jenkins/file-from-rest-of-path]")` or add this comment just before: `// lgtm[jenkins/file-from-rest-of-path]`
3. If this is a true positive finding, use the documentation below to resolve it.

If this finding is in a plugin hosted by the Jenkins project, you can also always [contact the Jenkins Security Team via Jira or email](https://www.jenkins.io/security/#reporting-vulnerabilities) to ask for help in resolving this finding.

## Is this a false positive?

It's legitimate to use `#getRestOfPath` to access a file. `DirectoryBrowserSupport` and other classes in Jenkins (core) do that as well. However, the value needs to be carefully sanitized, or the code needs to reject any values that could be used for path traversal. If your code is already doing that, and this check just didn't identify that, great!

## How can I fix the code?

Carefully consider the range of possible valid values and reject anything else. Some examples of bad values include:

* Anything starting with `../` or containing `/../` (as well as the variants with `\` on Windows)
* "Child" paths starting with a drive letter (Windows) may be considered absolute.
* "Child" paths with leading `/` may be considered absolute.
* If you're serving content from a location with user-contributed content, consider symbolic link following and make sure to confirm that the `File#getCanonicalPath` or equivalent of the file being accessed is within the canonical path of the root directory you're using.
