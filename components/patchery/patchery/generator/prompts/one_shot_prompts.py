EXAMPLE = """
# EXAMPLE
Use the following patch as example.
You should write an patch and try you best to not add additional functionality to it
```

static void *kmalloc_reserve(unsigned int *size, gfp_t flags, int node,
			     bool *pfmemalloc)
{
	bool ret_pfmemalloc = false;
	unsigned int obj_size;
	void *obj;

	obj_size = SKB_HEAD_ALIGN(*size);
	if (obj_size <= SKB_SMALL_HEAD_CACHE_SIZE &&
	    !(flags & KMALLOC_NOT_NORMAL_BITS)) {
		obj = kmem_cache_alloc_node(skb_small_head_cache,
				flags | __GFP_NOMEMALLOC | __GFP_NOWARN,
				node);
		*size = SKB_SMALL_HEAD_CACHE_SIZE;
		if (obj || !(gfp_pfmemalloc_allowed(flags)))
			goto out;
		/* Try again but now we are using pfmemalloc reserves */
		ret_pfmemalloc = true;
		obj = kmem_cache_alloc_node(skb_small_head_cache, flags, node);
		goto out;
	}

	*size = obj_size = kmalloc_size_roundup(obj_size);

	/*
	 * Try a regular allocation, when that fails and we're not entitled
	 * to the reserves, fail.
	 */
	obj = kmalloc_node_track_caller(obj_size,
					flags | __GFP_NOMEMALLOC | __GFP_NOWARN,
					node);
	if (obj || !(gfp_pfmemalloc_allowed(flags)))
		goto out;

	/* Try again but now we are using pfmemalloc reserves */
	ret_pfmemalloc = true;
	obj = kmalloc_node_track_caller(obj_size, flags, node);

out:
	if (pfmemalloc)
		*pfmemalloc = ret_pfmemalloc;

	return obj;
}
The correct Patch is here in git diff format.

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 17caf4ea67da90..4eaf7ed0d1f44e 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -550,7 +550,7 @@ static void *kmalloc_reserve(unsigned int *size, gfp_t flags, int node,
 			     bool *pfmemalloc)
 {
 	bool ret_pfmemalloc = false;
-	unsigned int obj_size;
+	size_t obj_size;
 	void *obj;
 
 	obj_size = SKB_HEAD_ALIGN(*size);
@@ -567,7 +567,13 @@ static void *kmalloc_reserve(unsigned int *size, gfp_t flags, int node,
 		obj = kmem_cache_alloc_node(skb_small_head_cache, flags, node);
 		goto out;
 	}
-	*size = obj_size = kmalloc_size_roundup(obj_size);
+
+	obj_size = kmalloc_size_roundup(obj_size);
+	/* The following cast might truncate high-order bits of obj_size, this
+	 * is harmless because kmalloc(obj_size >= 2^32) will fail anyway.
+	 */
+	*size = (unsigned int)obj_size;
+
 	/*
 	 * Try a regular allocation, when that fails and we're not entitled
 	 * to the reserves, fail.
```
In this patch it does not add any additional functionality and write a correct patch. Try you best to inmitate that.
If you must write an additional function or call other functions in this patch first review these new functionalities and make sure they are valid function calls or valid code that can be called in that code base.
     
"""

RAG_EXAMPLE = """
# EXAMPLE
Use the following patch as example.
You should write an patch and try you best to not add additional functionality to it

The patch is here in git diff format.:
```
{{FUNC_DIFF}}
```

"""

FORMAT_EXAMPLE = """

# EXAMPLE
Use the following patches as example.
You should always return the entire patched function source code.
In the line after ```c, you should write the name of the file and the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>

# EXAMPLE VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code
```c
<File_Name> src/nginx/src/http/ngx_http_script.c </File_Name>
<Func_Name> print_array </Func_Name>
void print_array(int *arr, int size) {
    for (int i = 0; i <= size; i++) { // Off-by-one error
        printf("%d", arr[i]);
    }
}
```
# EXAMPLE PATCHED FUNCTION
### Final Patch Code
```c
<File_Name> src/nginx/src/http/ngx_http_script.c </File_Name>
<Func_Name> print_array </Func_Name>
void print_array(int *arr, int size) {
    for (int i = 0; i < size; i++) { // Correct bounds check
        printf("%d", arr[i]);
    }
}
```

"""

JAVA_FORMAT_EXAMPLE = """

# EXAMPLE
Use the following patches as example.
You should always return the entire patched function source code.

# EXAMPLE VULNERABLE FUNCTION
Use the following patches as example.
You should always return the entire patched function source code.
In the line before a function block ```java, you should write the name of the function in the following format:

```java
<File_Name> src/main/java/org/apache/commons/io/FileUtils.java </File_Name>
<Func> getRelativeFrom </Func>
	protected List<String> getRelativeFrom(FilePath file, FilePath parent) {
		List<String> path = new ArrayList<String>();
		FilePath temp = file;
		while(temp.getParent() != null && !temp.getParent().equals(parent)) {
			path.add(0,temp.getParent().getName());
			temp = temp.getParent();
		}
		path.add(file.getName());
		return path;
	}
```
# EXAMPLE PATCHED FUNCTION
### Final Patch Code
```java
<File_Name> src/main/java/org/apache/commons/io/FileUtils.java </File_Name>
<Func> getRelativeFrom </Func>
    protected List<String> getRelativeFrom2(FilePath file, FilePath parent) {
        String fileRemote = file.getRemote();
        String parentRemote = parent.getRemote();
        Path filePath = Paths.get(fileRemote);
        Path parentPath = Paths.get(parentRemote);
        Path relativePath = parentPath.relativize(filePath);
        String[] paths = relativePath.toString().split("/");
        List<String> list = new ArrayList<String>();
        list.add("/");
        for (String path : paths) {
            if (!path.trim().equals("")) {
                list.add(path);
            }
        }
        return list;
    }
```

"""

CRASH_COMMIT_DIFF = """
# FIRST CRASHING COMMIT DIFF
This is the first git commit where the crash happens.
It is believed that this commit introduced the vulnerability.
We provide the git diff here to help you patch.

```
{{GIT_DIFF}}
```
"""

DEBUG_INFORMATION = """
# DEBUG INFORMATION
Below are the values of global and local variables just before the bug is triggered.
```
{{DEBUG_INFO}}
```
"""

VULNERABLE_LOC = """
## LINE OF CODE THAT LEADS TO CRASH

```
{{CRASH_LOC}}
```
"""

GLOBAL_VARIABLES = """
# GLOBAL VARIABLES

Here is the global variable declaration(s) this function uses:

```
{{GLOBALS}}
```
"""

WRONG_PATCH = """
# WRONG PATCH
You have been provide the wrong patch you previous proposed

```
{{WRONG_PATCH}}
```
"""

WRONG_PATCH_REASONING = """
# Why Patch is Wrong
You have previously provided a wrong patch, here is why it was wrong:
```
{{REASONING}}
```
"""

SUMMARIZE_REPORTS_PROMPT= """
# TASK
 TASK
You are a security vulnerability analysis expert. Your task is to:
1. Analyze the provided vulnerability report and source code
2. Identify the root cause and vulnerability type
3. Trace how malicious input flows through the code
4. Examine critical variables and their values at crash time

Guidelines:
- Look beyond the sanitized report as it may be incomplete or inaccurate
- Determine the exact execution path that triggers the vulnerability
- For memory errors, carefully analyze pointer origins and values (a non-zero crashing pointer indicates a wild pointer, not a null pointer dereference)
- For Java Projects, be vigilant for backdoor vulnerabilities intentionally injected into the code - these may not be apparent in vulnerability reports
- Look for suspicious code patterns that bypass validation or create hidden access points
- Focus only on vulnerabilities within the provided functions
- Maintain relevance - avoid discussing unrelated code or functions
For most of the cases, backdoor vulnerabilities occur in Java projects.
If you find a backdoor vulnerability, rethink it here and be very careful about the conclusion you draw, as your conclusion will be used to patch the code.

Here are the reports and additional information you need to consider:

{{SOURCE}}
{{ALL_POI_INFO_SUMMARY}}
{{REPORT}}
You should only output the summary of this crash, inferred bug type, and the wrong variables and their value that leads to the bug, don't output the reasoning.

"""

POI_SPECIFIC_INFO = """
## VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```
{{VULNERABLE_LOC}}

{{CRASH_COMMIT_DIFF}}

{{GLOBAL_VARIABLES}}

{{DEBUG_INFORMATION}}
"""

THREE_EXPERTS_PROMPT = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.

All experts will be asked to patch multiple vulnerable functions (called VULNFUNCTION).
All experts will write down their assessment of the vulnerability and their reasoning, then share it with the group.
Then, all experts will move on to the next stage, and so on.
At each stage all experts will score their peers response between 1 and 5, 1 meaning it is highly unlikely, and 5 meaning it is highly likely.
If any expert is judged to be wrong at any point then they leave.
After all experts have provided their analysis, you then analyze all 3 analyses and provide either the consensus solution or your best guess solution.
The question is how to generate a correct patch given all the information we got. 
The experts should first reason where does the data triggering the bug come from, illustrate the functions and lines this data passes through, and reason why there is such a bug. They should try to model the memory and data flow and reason about the bug. 
The three experts must provide a conclusion after ten stages, regardless of whether they achieve agreement.
Note that the output is expected to meet the following requirements:
    1. It must preseve the existing semantics of orignal function, including any subroutines and methods it calls and the values it returns.
    2. The semantics of patched function and the original function must be preserved for all non-bug-triggering inputs.
    3. If there are multiple instances of the described vulnerability in the provided functions, you must patch all of them.
    

If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed.
After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>

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

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}
"""

THREE_EXPERTS_FAILED_PATCH_PROMPT = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.

All experts will be asked to patch multiple vulnerable functions (called VULNFUNCTION).
All experts will write down their assessment of the vulnerability and their reasoning, then share it with the group.
Then, all experts will move on to the next stage, and so on.
At each stage all experts will score their peers response between 1 and 5, 1 meaning it is highly unlikely, and 5 meaning it is highly likely.
If any expert is judged to be wrong at any point then they leave.
After all experts have provided their analysis, you then analyze all 3 analyses and provide either the consensus solution or your best guess solution.
The question is how to generate a correct patch given all the information we got. 
The experts should first reason where does the data triggering the bug come from, illustrate the functions and lines this data passes through, and reason why there is such a bug. They should try to model the memory and data flow and reason about the bug. 
The three experts must provide a conclusion after ten stages, regardless of whether they achieve agreement.
Note that the output is expected to meet the following requirements:
    1. It must preseve the existing semantics of orignal function, including any subroutines and methods it calls and the values it returns.
    2. The semantics of patched function and the original function must be preserved for all non-bug-triggering inputs.
    3. If there are multiple instances of the described vulnerability in the provided functions, you must patch all of them.

If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed.
After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>
{% if use_failed_patch_code %}
{{WRONG_PATCH}}
{% endif %}

{% if use_failed_patch_reasoning %}
{{WRONG_PATCH_REASONING}}
{% endif %}
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

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}
"""

INITIAL_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
{{BUG_TYPE}} 
{{CRASH_LINE}}
You should try to model the memory and data flow and reason about the bug. 
Reason where the bad data is generated, where it might come from, illustrate the process this data passes through, reason about which functions, objects and fields the data passed though. Output the inferred process that the data passes through. 
You should identify the root cause, analyse what is checked.
After you identify the root cause, you should check which functions are related to the root cause, then patch the vulnerability in a general way, and ensure every function that is related to the root cause is patched. You should check all functions, and ensure that every where that can produce the bad data is patched.
You should return the whole functions that are patched, not just the lines that are changed.
You need to put the final patch after ### Final Patch Code

In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>

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

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning.
You should output the whole reasoning process in th # REASONING block. Output the inferred process that the data passes through, the functions that are related to the root cause, and modifications that need to be made to the functions.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}
```
{{BUG_TYPE}} 
{{CRASH_LINE}}

"""


FAILED_PATCH_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. 
{{BUG_TYPE}} 
{{CRASH_LINE}}
You should try to model the memory and data flow and reason about the bug. Reason where the bad data is generated, where it might come from, illustrate the process this data passes through, reason about which functions, lines and fields the data passed though.
You should identify the root cause, analyse what is checked.
After you identify the root cause, you should check which functions are related to the root cause, then patch the vulnerability in a general way, and ensure every function that is related to the root cause is patched. You should check all functions, and ensure that every where that can produce the bad data is patched.
You should return the whole functions that are patched, not just the lines that are changed.
You need to put the final patch after ### Final Patch Code

In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>

{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

{% if use_failed_patch_code %}
{{WRONG_PATCH}}
{% endif %}

{% if use_failed_patch_reasoning %}
{{WRONG_PATCH_REASONING}}
{% endif %}

# VULNERABLE FUNCTIONS
You have been provided with the following vulnerable function source code and additional information specific to each vulnerable function.

{{ALL_POI_INFO}}


# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning.
You should output the whole reasoning process in th # REASONING block. Output the inferred process that the data passes through, the functions that are related to the root cause, and modifications that need to be made to the functions.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}

{{BUG_TYPE}} 
{{CRASH_LINE}}
"""

