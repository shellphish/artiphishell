import logging
import whatthepatch
from agentlib.lib import tools

from shellphish_crs_utils.function_resolver import LocalFunctionResolver, FUNCTION_INDEX_KEY
import re

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

PeekDiffSkillGlobal = None

from .peek_utils import tool_error, tool_success, tool_choice

#########################
##### 🔨 LLM Tools ######
#########################

# @tools.tool
def get_diff_snippet(func_index: FUNCTION_INDEX_KEY):
    global PeekDiffSkillGlobal
    return PeekDiffSkillGlobal.get_func_diff(func_index)

# @tools.tool
def list_changed_functions(file_path: str):
    global PeekDiffSkillGlobal
    return PeekDiffSkillGlobal.list_changed_funcs(file_path)


class PeekDiffSkill:
    def __init__(self, **kwargs):
        self.func_resolver = kwargs["function_resolver"]
        self.diff_file = kwargs["diff_file"]
        
        log.info(f'⚙️ Initializing function resolver for the changed_function_index')
        self.changed_func_resolver = LocalFunctionResolver (
                functions_index_path=kwargs["changed_functions_index"],
                functions_jsons_path=kwargs["changed_functions_jsons_dir"]
            )
        
        global PeekDiffSkillGlobal
        PeekDiffSkillGlobal = self

    def get_func_diff(self, function_index: FUNCTION_INDEX_KEY, bot=False):
        with open(self.diff_file, "r") as f:
            diff_text = f.read()
        
        path = str(self.func_resolver.get(function_index).target_container_path)
        name = self.func_resolver.get_funcname(function_index)
        boundary = self.func_resolver.get_function_boundary(function_index)
        ALL_TEXT = ""
        flag = 0
        for diff in whatthepatch.parse_patch(diff_text):
            if  diff.header.new_path not in path:
                continue
            match = re.split(r"(@@ -\d+,\d+ \+\d+,\d+ @@)", diff.text)
            results_tmp = {}
            text = match[0]
            for snippet in match[1:]:
                if snippet.startswith("@@"):
                    match_header = re.match(r"@@ -(\d+),\d+ \+(\d+),(\d+) @@", snippet)
                    base_line = int(match_header.group(1))
                    target_line = int(match_header.group(2))
                    changed_lines = int(match_header.group(3))
                    if  boundary[0]>target_line+changed_lines or boundary[1]<target_line:
                        should_include = False
                    else:
                        should_include = True
                        text += (snippet+match[match.index(snippet) + 1])+ "\n"
                        flag = 1
                        # print("Found diff for function %s in file %s" % (name, path))

                    results_tmp[snippet] = {
                        "target_line": target_line,
                        "base_line": base_line,
                        "snippet": snippet + match[match.index(snippet) + 1],
                        "include": should_include
                    }
            ALL_TEXT += text

        if flag == 0:
            log.info("Can't find diff for function %s in file %s" % (name, path))
            if bot == True:
                return tool_error(f"The code  `{name}` was not changed in the diff file!")
            else:
                return None
        else:
            log.info("Found diff for function %s in file %s" % (name, path))
            if bot == True:
                return tool_success(ALL_TEXT)
            else:
                return ALL_TEXT
            
    def list_changed_funcs(self, file_path: str, bot=False):
        with open(self.diff_file, "r") as f:
            diff_text = f.read()
            
        funcs_in_file = list(self.func_resolver.find_by_filename(file_path))
        if not funcs_in_file:
            return tool_error(f"No functions in the file {file_path}")
        
        flag = 0
        
        for diff in whatthepatch.parse_patch(diff_text):
            if diff.header.new_path not in file_path:
                continue
            match = re.split(r"(@@ -\d+,\d+ \+\d+,\d+ @@)", diff.text)
            changed=set()
            
            for snippet in match[1:]:
                if snippet.startswith("@@"):
                    match_header = re.match(r"@@ -(\d+),\d+ \+(\d+),(\d+) @@", snippet)
                    base_line = int(match_header.group(1))
                    target_line = int(match_header.group(2))
                    changed_lines = int(match_header.group(3))
                    for func in funcs_in_file:
                        boundary = self.func_resolver.get_function_boundary(func)
                        if not (boundary[0]>target_line+changed_lines or boundary[1]<target_line):
                            changed.add(f"{self.func_resolver.get_funcname(func)} at line {boundary[0]}")
                    
            if len(changed):
                flag=1
                ALL_TEXT = '\n'.join(list(changed))
            else:
                flag=0

        if flag == 0:
            log.info("No functions changed in file %s" % (file_path))
            if bot == True:
                return tool_error(f"No functions changed in file {file_path}")
            else:
                return f"No functions changed in file {file_path}"
        else:
            log.info("Found changed functions in file %s" % (file_path))
            if bot == True:
                return tool_success(ALL_TEXT)
            else:
                return ALL_TEXT
