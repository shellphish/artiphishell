FORMAT_EXAMPLE = """
# Example Format for Code Diff Generation

File: mathutils/compute.c - calculate_factorial()
```
<<<<<<< SEARCH
    if (n == 0) return 1;
    return n * factorial(n - 1);
=======
    if (n < 0) return -1;  // Error case
    if (n == 0) return 1;
    
    // Check for integer overflow
    if (n > 12) return -1;
    
    int result = 1;
    for (int i = 1; i <= n; i++) {
        result *= i;
    }
    return result;
>>>>>>> REPLACE
```

File: mathutils/compute.c - calculate_square_root()
```
<<<<<<< SEARCH
    return x * x;
=======
    if (x < 0) return -1;  // Error case
    if (x == 0) return 0;
    
    double guess = x / 2;
    double epsilon = 0.00001;
    
    while (fabs(guess * guess - x) > epsilon) {
        guess = (guess + x / guess) / 2;
    }
    return guess;
>>>>>>> REPLACE
```

Instructions:
1. Each code diff should start with the file path and function name using the format:
   `filepath/filename.c - function_name()`
   the file path can be found in # VULNERABLE FUNCTIONS section in this format: `<File_Name> file_path </File_Name>`

2. Use the following markers consistently:
   - `<<<<<<< SEARCH` for the original code snippet
   - `=======` as the separator
   - `>>>>>>> REPLACE` for the new code snippet

3. Include proper indentation and formatting in both sections

4. If multiple functions are modified, separate them with a blank line

5. Put the code diff in ### Final Patch Code section and place this section at the end of the output

6. Do not include any additional comments or instructions in the code diff

7. Make sure to make the diff as minimal as possible and only include the affected code snippets not the entire function

8. If the function is not modified, do not include it in the code diff

"""

INITIAL_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
You should try to model the memory and data flow and reason about the bug. 
Reason where the bad data is generated, where it might come from, illustrate the process this data passes through, reason about which functions, 
objects and fields the data passed though. Output the inferred process that the data passes through. 
You should identify the root cause, analyse what is checked.
After you identify the root cause, you should check which functions are related to the root cause, then patch the vulnerability in a general way, 
and ensure every function that is related to the root cause is patched. You should check all functions, and ensure that every where that can produce the bad data is patched.
You need to put the output in # FINAL OUTPUT section.

{{EXAMPLE}}

# VULNERABLE FUNCTIONS
You have been provided with the following vulnerable function source code and additional information specific to each vulnerable function.

{{ALL_POI_INFO}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

# VULNERABILITY SUMMARY

{{VUL_SUMMARY}}

# OUTPUT FORMAT
In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
Follow the format of the following example:
{{FORMAT_EXAMPLE}}

"""

FAILED_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
You should try to model the memory and data flow and reason about the bug. 
Reason where the bad data is generated, where it might come from, illustrate the process this data passes through, reason about which functions, 
objects and fields the data passed though. Output the inferred process that the data passes through. 
You should identify the root cause, analyse what is checked.
After you identify the root cause, you should check which functions are related to the root cause, then patch the vulnerability in a general way, 
and ensure every function that is related to the root cause is patched. You should check all functions, and ensure that every where that can produce the bad data is patched.
If you are provided with a wrong patch, you should check the patch and why does it fail in the firest place.
Combine the information you have and the information you got from the failed patch and think hard and think step by step.
You need to put the output in # FINAL OUTPUT section and follow the format example given below.
DO NOT CHANGE THE FORMAT OF THE OUTPUT.
You should only consider that the vulnerability is in the functions provided. 
Do not output info that is not related to the functions provided.
{% if use_failed_patch_code %}
{{WRONG_PATCH}}
{% endif %}

{% if use_failed_patch_reasoning %}
{{WRONG_PATCH_REASONING}}
{% endif %}

# OUTPUT FORMAT
In the line after ```c|java|python|, you should write the name of the function in the following format:
Follow the format of the following example and put the final patch after ### Final Patch Code:
{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

# VULNERABLE FUNCTIONS
You have been provided with the following vulnerable function source code and additional information specific to each vulnerable function.

{{ALL_POI_INFO}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

# VULNERABILITY SUMMARY
{{VUL_SUMMARY}}

# FINAL OUTPUT
{REASONING}

## Final Patch Code
{PATCH}

"""