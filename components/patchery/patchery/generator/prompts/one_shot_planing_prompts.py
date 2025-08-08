CRASH_COMMIT_DIFF = """
# FIRST CRASHING COMMIT DIFF
This is the first git commit where the crash happens.
It is believed that this commit introduced the vulnerability.
We provide the git diff here to help you patch.

```
{{GIT_DIFF}}
```
"""

SOURCE_CODE = """
You have been provided with the following vulnerable function source code
{{SOURCE}}
"""

DEBUG_INFORMATION = """
# DEBUG INFORMATION
Below are the values of global and local variables just before the bug is triggered.
```
{{DEBUG_INFO}}
```
"""

TOOLS_REASONING = """
# TOOLS REASONING
Below are the reasoning of the tools used to generate the patch.
```
{{STRATEGY}}
```

"""

THREE_EXPERTS_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
You must try to model the memory and data flow and reason about the bug. Reason where the bad data is generated, where does it come from, from which function and from which line of code, illustrate the functions and lines this data passes through.
You must identify the root cause, analyse what is checked, and what is not checked. 
After you identify the root cause, you must check which functions are related to the root cause, then patch the vulnerability in a general way, and ensure every function that is related to the root cause is patched. 
You must return the whole functions that are patched, not just the lines that are changed.
YOU MUST FOLLOW THE FORMAT BELOW

After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you must write the name of the function in the following format:
```c|java|python|
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>
```
Here is an example of the format you must use to patch the function:
YOU MUST FOLLOW THIS FORMAT
{{FORMAT_EXAMPLE}}

# VULNERABLE FUNCTIONS
```
{{SOURCE}}
```

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

{{TOOLS_REASONING}}

{% if use_expert_reasoning %}
You must only give us the entire patched function source code and the reasoning. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code must be put in reasoning.

# REASONING
{REASONING}
{% else %}
You must only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.

{% endif %}

"""

THREE_EXPERTS_FAILED_PATCH_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
{{BUG_TYPE}} 
{{CRASH_LINE}}
You must try to model the memory and data flow and reason about the bug. Reason where the bad data is generated, where does it come from, from which function and from which line of code, illustrate the functions and lines this data passes through.
You must identify the root cause, analyse what is checked, and what is not checked. 
After you identify the root cause, you must check which functions are related to the root cause, then patch the vulnerability in a general way, and ensure every function that is related to the root cause is patched. 
You must return the whole functions that are patched, not just the lines that are changed.
YOU MUST FOLLOW THE FORMAT BELOW

After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you must write the name of the function in the following format:
```c|java|python|
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>
```

Here is an example of the format you must use to patch the function:
YOU MUST FOLLOW THIS FORMAT
{{FORMAT_EXAMPLE}}

{% if use_failed_patch_code %}
# WRONG PATCH
You have been provide the wrong patch you previous proposed

```
{{WRONG_PATCH}}
```
{% endif %}

{% if use_failed_patch_reasoning %}
#Why Patch is Wrong
You have previously provided a wrong patch, here is why it was wrong:
```
{{REASONING}}
```
{% endif %}

# VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

{{TOOLS_REASONING}}

{% if use_expert_reasoning %}
You must only give us the entire patched function source code and the reasoning. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code must be put in reasoning.

# REASONING
{REASONING}
{% else %}
You must only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.

{% endif %}

"""