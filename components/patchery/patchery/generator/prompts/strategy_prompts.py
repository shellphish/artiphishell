STRATEGY_PROMPT = """
# SUMMARIZATION OF THE CODE 
Below are the summarization of the code and crash report.
```
{{SUMMARY}}
```

"""

DEBUG_INFO_PROMPT = """
## DEBUG INFORMATION for this function {{FUNC_NAME}}
{{DEBUG_INFO}}
"""