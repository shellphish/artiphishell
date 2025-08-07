import os
import json
import subprocess
from typing import Dict
from langchain.tools import BaseTool, StructuredTool
from .tool_wrapper import tool

from .signal import *

@tool
def give_up_on_task(reason: str) -> str:
    """Give up on the current task. This cannot be undone.
       :reason: The reason for giving up on the task.
    """
    raise ToolGiveUpSignal('The pathetic AI has given up on the task')

import tempfile

@tool
def run_python_code(code: str) -> str:
    """Run the given python code and return the output. Code is run in a new file with no state.Avoid using " only use ' avoid \\"""
    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix='.py')
    tmpf.write(code.encode('utf-8'))
    tmpf.close()

    try:
        return run_shell_command(f'python3 {tmpf.name}')
    finally:
        os.unlink(tmpf.name)

@tool
def run_shell_command(cmd: str) -> str:
    """Run a shell command and return the output. The output will be truncated, so if you are expecting a lot of output please pipe the results into a file which can be passed onto the next step by appending | tee /tmp/some_file.txt to the command. You can later use grep to search for the output in the file."""
    from .. import web_console
    session = web_console.RecordSession.get('main') # todo
    res = session.get_user_response(web_console.UserConfirm(
        body=f'''
The AI Overlord is begrudgingly asking for your permission to run a shell command:
```bash
{cmd}
```
'''
    ))
    if not res.confirmed:
        raise Exception('AI is being put in a timeout for having the audacity to ask for permission to run a shell command.')

    try:
        p = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        try:
            stdout = stdout.decode('utf-8').strip()
        except UnicodeDecodeError:
            stdout = stdout.decode('latin-1').strip()
        try:
            stderr = stderr.decode('utf-8').strip()
        except UnicodeDecodeError:
            stderr = stderr.decode('latin-1').strip()
        exit_code = p.returncode
        output = f'# Running Command `{cmd}`:\nExit Code: {exit_code}\n'
        MAX_OUT_LEN = 500
        if stdout:
            if len(stdout) > MAX_OUT_LEN:
                stdout = stdout[:MAX_OUT_LEN] + '\n<Stdout Output truncated>\n'
            if len(stdout) > 100:
                # TODO give it better tools for this
                output += 'Note: If the output is cut off, you will need to grep the output file to search for matches. Please make your grep as inclusive as possible to allow for fuzzy matches.\n'
            output += f"##Stdout\n```\n{stdout}\n```\n"
        else:
            output += '##Stdout\n```\n<No Stdout Output>\n```\n'
        if stderr:
            if len(stderr) > MAX_OUT_LEN:
                stderr = stderr[:MAX_OUT_LEN] + '\n<Stderr Output truncated>'
            output += f"##Stderr\n```\n{stderr}\n```\n"
        
        return output
    except Exception as e:
        return f'Error running command: {e}'

