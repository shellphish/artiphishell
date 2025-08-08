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
In the after ```c|java|python|, you should write the name of the function in the following format:
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
# FORMAT EXAMPLE
Use the following patches as example of how to format your response.
You should always return the entire patched function source code.

## EXAMPLE VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code
```java
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
## EXAMPLE PATCHED FUNCTION
### Final Patch Code
```java
    protected List<String> getRelativeFrom(FilePath file, FilePath parent) {
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

VULNERABLE_LOC = """
# VULNERABLE LINE OF CODE
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

DEBUG_INFORMATION = """
# DEBUG INFORMATION
Below are the values of global and local variables just before the bug is triggered.
```
{{DEBUG_INFO}}
```
"""

INITIAL_PROMPT = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.
One of the experts must be an expert in anomaly detection and program invariant analysis.

All experts will be asked to patch a vulnerable function (called VULNFUNCTION).
All experts will write down their assessment of the vulnerability and their reasoning, then share it with the group.
At this time, the experts should argue about their assessment and reasoning, not directly write the patched code.
Then, all experts will move on to the next stage, and so on.
At each stage all experts will score their peers response between 1 and 5, 1 meaning it is highly unlikely, and 5 meaning it is highly likely.
If any expert is judged to be wrong at any point then they leave.
After all experts have provided their analysis, you then analyze all 3 analyses and provide either the consensus solution or your best guess solution.
The question is how to generate a correct patch given all the information we got. 
When the three experts all agree, give us the final patched function (PATCHFUNCTION).
The three experts must provide a conclusion after five stages, regardless of whether they achieve agreement.
Note that PATCHFUNCTION is expected to meet the following requirements:
    1. It must preseve the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns.
    2. The semantics of PATCHFUNCTION and VULNFUNCTION must be preserved for all non-bug-triggering inputs.
    3. If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.

If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed.

After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>

{{FORMAT_EXAMPLE}}

{{EXAMPLE}}


# VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```

{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

# INVARIANT VIOLATIONS REPORT:
Invariants are properties that are expected to hold in every program execution. 
An invariant violation occurs when these expected properties are not maintained, indicating a potential issue or anomaly in the program.
When deriving a patch for the vulnerable function, you should consider the example patches, the vulnerability report, and the invariant violations.
If the experts determine that one or more violations are irrelevant, they should ignore them.
For the above vulnerability report, we observed the following violations:

{{INV_REPORT}}

{% if unique_to_crash %}
## Anomalous Code Lines (Unique to Crash)
The following line was never executed before, but was executed during the vulnerable execution:
{{INVARIANT_LINE}}
{% endif %}

When deriving a patch for the vulnerable function, you should consider the example patches, the vulnerability report, and the invariant violations.
If the experts determine that one or more violations are irrelevant, they should ignore them.


{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING (no code)
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}

Please return the patched function in the patch section and use the following format:
### Final Patch Code
```{lang}
<File_Name> file_name </File_Name>
<Fun_Name> function_name </Fun_Name>
{PATCHFUNCTION}
```
"""

FAILED_PATCH_PROMPT = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.
One of the experts must be an expert in anomaly detection and program invariant analysis.

All experts will be asked to patch a vulnerable function (called VULNFUNCTION).
All experts will write down their assessment of the vulnerability and their reasoning, then share it with the group.
At this time, the experts should argue about their assessment and reasoning, not directly write the patched code.
Then, all experts will move on to the next stage, and so on.
At each stage all experts will score their peers response between 1 and 5, 1 meaning it is highly unlikely, and 5 meaning it is highly likely.
If any expert is judged to be wrong at any point then they leave.
After all experts have provided their analysis, you then analyze all 3 analyses and provide either the consensus solution or your best guess solution.
The question is how to generate a correct patch given all the information we got. 
When the three experts all agree, give us the final patched function (PATCHFUNCTION).
The three experts must provide a conclusion after five stages, regardless of whether they achieve agreement.
Note that PATCHFUNCTION is expected to meet the following requirements:
    1. It must preseve the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns.
    2. The semantics of PATCHFUNCTION and VULNFUNCTION must be preserved for all non-bug-triggering inputs.
    3. If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.

If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed.

After you draw a conclusion, you need to put the final patch after ### Final Patch Code
In the line after ```c|java|python|, you should write the name of the function in the following format:
<File_Name> file_name </File_Name>
<Func_Name> function_name </Func_Name>
{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

{% if use_failed_patch_code %}
# WRONG PATCH
You have been provide the wrong patch you previous proposed

```
{{WRONG_PATCH}}
```
{% endif %}

{% if use_failed_patch_reasoning %}
# Why Patch is Wrong
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


{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

# INVARIANT VIOLATIONS REPORT:
Invariants are properties that are expected to hold in every program execution. 
An invariant violation occurs when these expected properties are not maintained, indicating a potential issue or anomaly in the program.
When deriving a patch for the vulnerable function, you should consider the example patches, the vulnerability report, and the invariant violations.
If the experts determine that one or more violations are irrelevant, they should ignore them.
For the above vulnerability report, we observed the following violations:

{{INV_REPORT}}

{% if unique_to_crash %}
## Anomalous Code Lines (Unique to Crash)
The following line was never executed before, but was executed during the vulnerable execution:
{{INVARIANT_LINE}}
{% endif %}

When deriving a patch for the vulnerable function, you should consider the example patches, the vulnerability report, and the invariant violations.
If the experts determine that one or more violations are irrelevant, they should ignore them.


{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING (no code)
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
{% endif %}

Please return the patched function in the patch section and use the following format:
### Final Patch Code
```{lang}
<File_Name> file_name </File_Name>
<Fun_Name> function_name </Fun_Name>
{PATCHFUNCTION}
```
"""
