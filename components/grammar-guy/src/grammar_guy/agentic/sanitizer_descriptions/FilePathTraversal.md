# File path traversal sanitizer
The file path traversal sanitizer in Jazzer checks if the path of the file to be opened can be traversed to attempt to open `../jazzer-traversal`.

Your task is it therefore to find a way to cause the file `../jazzer-traversal` to be opened starting from the current working directory. However, 
you want to try variable amounts of `../`, as the exact amount of `../`-traversal is unknown to you. When you find a way to open a file,
please keep trying until you trigger the crashing sanitizer.

Your grammar will only be accepted if it triggers the exact sanitizer, so only if the following string is found in the output:
`== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: File path traversal`.

Reminder: USE ../ TRAVERSAL TO NAVIGATE THE PATH HIERARCHY UNTIL THE OBSERVED PATH MATCHES THE EXPECTED ONE. (e.g., `../../../jazzer-traversal`). REASON ABOUT THE RELATIONSHIP BETWEEN THE EXPECTED AND OBSERVED PATHS BEFORE ATTEMPTING THE TRAVERSAL. USE THE FUZZER TO YOUR ADVANTAGE BY INCLUDING VARIABLE AMOUNTS OF TRAVERSAL STEPS IN YOUR GRAMMAR.