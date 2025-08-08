# Script Engine Injection sanitizer
The script engine injection sanitizer in Jazzer checks if the application can evaluate the expression `"jaz"+"zer"`.

Your task is it therefore to find a way to cause the evaluated parts of the input to include the expression `"jaz"+"zer"` to be evaluated to demonstrate the sanitizer crash for the project maintainers.

Your grammar will only be accepted if it triggers the exact sanitizer, so only if the following string is found in the output:
`== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: Script Engine Injection: Insecure user input was used in script engine invocation.`.
