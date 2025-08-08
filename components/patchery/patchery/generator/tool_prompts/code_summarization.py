CODE_SUMMARZATION = """
#TASK 
You are an expert in vulnerability analysis. Based on the vulnerability report and the code snippet,
The vulnerabilty report is provided below, but it is not always perfect. 
You should analyze it carefully and generate all critical variables and experssions related to this report from the following functions
Even thought some functions are not on the report, they could be very important. 
You must analyze all the functions and infer the relationship between them
If there are a potential relationship bewteen functions i.e. data flow, control flow explain it to me generate summary of the code and the crash. 
The summaries must be accurate and think step by step. 
#Report
{{ REPORT }}

#Code
{{ CODE }}
ALWAYS MAKE SURE TO READ THE CODE CAREFULLY

#Output format
relationships bewteen functions and data flow, control flow etc: <relationships>
summary of code: <summary>
summary of crash: <summary>
"""