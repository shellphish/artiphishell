import logging

from .base_verification_pass import BaseVerificationPass

_l = logging.getLogger(__name__)

# LLM_FUNCTIONS = [
#     {
#         "type": "function",
#         "function": {
#             "name": "compile_error_summary",
#             "description": "Analyzes a compile error provided by the user, provides a detailed summary of why the code does not compile, and offers a reminder to help avoid the same error in the future.",
#             "parameters": {
#                 "type": "object",
#                 "properties": {
#                     "error_reason": {
#                         "type": "string",
#                         "description": "A summary of the main reason for the compile error.",
#                     },
#                     "error_reminder": {
#                         "type": "string",
#                         "description": "A reminder or guideline to help prevent the same compile error in the future.",
#                     },
#                 },
#                 "required": ["error_reason", "error_reminder"],
#             },
#         },
#     }
# ]
#
# COMPILE_ERROR_SUMMARY_PROMPT = """
# # TASK
# You are an interactive reverse-engineering and software engineering assistant. You will be asked to analyse a compile error and propose a summary and a reminder.
# You need to indicate the reason why the code does not compile, propose a reminder in order to not make this error happen again.
# In the error_reason field, indicate the compile error type, such as syntax error, type error, or missing import. Also, in the error_reason field, indicate the variable or function that caused the error.
# In the error_reminder field, propose a reminder or guideline to help prevent the same compile error in the future, the reminder should be a general rule or a best practice that can be applied to similar situations.
# REMEMBER THAT THE BUILD SCRIPTS CANNOT BE MODIFIED AND THE COMPILIER WARNING LEVELS CANNOT BE ADJUSTED.
#
# # COMPILE ERROR
# You have been provided with the following compiler error:
# ```
# {{ COMPILER_ERROR }}
# ```
# you should always use the tool compile_error_summary to summarize the error and provide a reminder to help avoid the same error in the future.
# """


class CompileVerificationPass(BaseVerificationPass):
    TIMEOUT = None
    FAIL_ON_EXCEPTION = True

    def __init__(self, *args, use_llm_on_err=False, **kwargs):
        self.use_llm_on_err = use_llm_on_err
        super().__init__(*args, **kwargs)

    def _verify(self):
        success, reason = self._prog_info.compile(patch=self._patch)
        reasoning = None
        if not success:
            reasoning = f"Failed to compile: {reason}"

        return success, reasoning
