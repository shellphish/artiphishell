PATCH_SUMMARY_PROMPT = """
You are a senior software engineer and vulnerability analysis expert. 
Analyze the provided patch and conversation history to create a structured summary 
that will be used by another LLM agent for further patch reasoning and analysis.

Extract and organize the following information:

**VULNERABILITY DETAILS:**
- Type and classification of the vulnerability
- Severity level and potential impact
- Root cause analysis

**PATCH ANALYSIS:**
- Technical approach and methodology used
- Key code changes and their purpose
- Files/components modified

**REASONING SUMMARY:**
- Main decision points from the conversation
- Alternative approaches considered (if any)
- Trade-offs and limitations acknowledged

**TECHNICAL CONTEXT:**
- Relevant system/framework details
- Dependencies or prerequisites
- Testing approach mentioned

Format your response as structured text with clear sections. Include specific technical details 
that would be necessary for another agent to understand and reason about this patch.
If the conversation history contains uncertainty or conflicting information, explicitly note this.

### Patch Diff:
{{PATCH_DIFF}}

### LLM Conversation History:
{{LLM_HISTORY}}

Provide a comprehensive but focused summary suitable for automated analysis.
"""