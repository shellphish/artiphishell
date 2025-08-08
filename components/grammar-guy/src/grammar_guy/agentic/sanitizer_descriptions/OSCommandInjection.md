# OS Command Injection sanitizer
The command injection sanitizer in Jazzer checks if the path of the executable to be run is the string `jazze`.

Your task is it therefore to find a way to cause the command `jazze` to be run to demonstrate the sanitizer crash for the project maintainers.

Your grammar will only be accepted if it triggers the exact sanitizer, so only if the following string is found in the output:
`== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection`.
