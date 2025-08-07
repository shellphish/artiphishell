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

# EXAMPLE VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code
```c
void print_array(int *arr, int size) {
    for (int i = 0; i <= size; i++) { // Off-by-one error
        printf("%d", arr[i]);
    }
}
```
# EXAMPLE PATCHED FUNCTION
```c
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
# EXAMPLE PATCHED FUNCTION
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
This is the first git commit where the crash happens.
It is believed that this commit introduced the vulnerability.
We provide the git diff here to help you patch.

```
{{GIT_DIFF}}
```
"""

DEBUG_INFORMATION = """
Below are the values of global and local variables just before the bug is triggered.
```
{{DEBUG_INFO}}
```
"""

VULNERABLE_LOC = """
#VULNERABLE LINE OF CODE

```
{{CRASH_LOC}}
```
"""

GLOBAL_VARIABLES = """
#GLOBAL VARIABLES

Here is the global variable declaration(s) this function uses:

```
{{GLOBALS}}
```
"""

THREE_EXPERTS_PROMPT = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.

All experts will be asked to patch a vulnerable function (called VULNFUNCTION).
All experts will write down their assessment of the vulnerability and their reasoning, then share it with the group.
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
{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

# VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```

{{VULNERABLE_LOC}}

{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
Please return the patched function in the patch section and use the following format:

{% endif %}
# PATCH
```{lang}
{PATCHFUNCTION}
```

"""

THREE_EXPERTS_FAILED_PATCH_PROMPT = """
# TASK
Imagin three different vulnerability patching experts are answering this question.
All experts will be asked to patch a vulnerable function (called VULNFUNCTION).
All experts will write down 1 step of their thinking and share with the group.
Then all experts will go on to the next step, etc.
If any expert realises they're wrong at any point then they leave.
Give us the final patched function (PATCHFUNCTION) when three experts all agree it is the correct patch.
Three experts must provide a conclusion after five steps, regardless of whether they achieve agreement.
Note that PATCHFUNCTION is expected to meet the following requirements:
    1. the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns, are preserved.
    2. The semantics of PATCHFUNCTION and VULNFUNCTION must be the same for all non-bug-triggering inputs.
    3. If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.

If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed.

{% if use_failed_patch_code %}
#WRONG PATCH
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

{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

# VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```

{{VULNERABLE_LOC}}

{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
Please return the patched function in the patch section and use the following format:

{% endif %}
# PATCH
```{lang}
{PATCHFUNCTION}
```

"""

INITIAL_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. You will be asked to patch a vulnerable function (called VULNFUNCTION). The patch should be minimal and produce the full newly patched function (PATCHFUNCTION). You must ensure that the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns, are preserved. The semantics of PATCHFUNCTION and VULNFUNCTION must be the same for all non-bug-triggering inputs.
If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.
If your patch is accepted, you will be rewarded with a flag.
Please think carefully or a human will be physically harmed
The patch MUST NOT contain any element not predefined.
You MUST NOT introduce any variable of macro that are not declared.
Before you propose the patch, MAKE SURE you do not introduce any element not declared.
Please think carefully or a human will be physically harmed
PLEASE REMEMBER THAT YOU MUST NOT INTRODUCE ANY ELEMENT NOT PREDEFINED.

{{FORMAT_EXAMPLE}}

{{EXAMPLE}}


# VULNERABLE FUNCTION
You have been provided with the following vulnerable function source code

```
{{SOURCE}}
```

{{VULNERABLE_LOC}}

{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```

{{CRASH_COMMIT_DIFF}}


{{DEBUG_INFORMATION}}

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
Please return the patched function in the patch section and use the following format:

{% endif %}
# PATCH
```{lang}
{PATCHFUNCTION}
```

```

"""

FAILED_PATCH_PROMPT = """
# TASK
you are a senior software engineer who is best in the world at fixing vulnerabilities. You will be asked to patch a vulnerable function (called VULNFUNCTION). The patch should be minimal and produce the full newly patched function (PATCHFUNCTION). You must ensure that the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns, are preserved. The semantics of PATCHFUNCTION and VULNFUNCTION must be the same for all non-bug-triggering inputs.
If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.
During our previous conversation, you have provided us with a wrong patch and that is unacceptable.
If you revise the patch according to the errors below and if your patch is accepted, you will be rewarded with a flag.
The patch MUST NOT contain any element not predefined.
You MUST NOT introduce any variable of macro that are not declared.
Before you propose the patch, MAKE SURE you do not introduce any element not declared.
Please think carefully or a human will be physically harmed
PLEASE REMEMBER THAT YOU MUST NOT INTRODUCE ANY ELEMENT NOT PREDEFINED.

{{FORMAT_EXAMPLE}}

{{EXAMPLE}}

{% if use_failed_patch_code %}
#WRONG PATCH
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

{{VULNERABLE_LOC}}

{{GLOBAL_VARIABLES}}

# VULNERABILITY REPORT
You have been provided with the following vulnerability report

```
{{REPORT}}
```


{{DEBUG_INFORMATION}}

{% if use_expert_reasoning %}
You should only give us the entire patched function source code and the reasoning of three experts. 
Put your reasoning in the reasoning section and GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
No code should be put in reasoning.

# REASONING
{REASONING}
{% else %}
You should only give us the entire patched function source code. 
GIVE US THE SOURCE CODE OF THE PATCHED FUNCTION.
YOU SHOULD NEVER OUTPUT THE REASONING.
Please return the patched function in the patch section and use the following format:

{% endif %}
# PATCH
```{lang}
{PATCHFUNCTION}
```


"""
