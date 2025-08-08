import os
import json
import logging
import hashlib
import whatthepatch
from agentlib.lib import tools
from pprint import pprint
from rich import print
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.symbols import RelativePathKind
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver
from analysis_graph.models.cfg import CFGFunction
from shellphish_crs_utils.models.coverage import FileCoverageMap, FunctionCoverageMap
import re
log = logging.getLogger("discoveryguy.peek_diff")


PeekDiffSkillGlobal = None


from .peek_utils import tool_error, tool_success, tool_choice

#########################
##### 🔨 LLM Tools ######
#########################

@tools.tool
def get_diff_snippet(function_index: str):
    """
    Get the diff snippet for a given function index. The diff snippet shows the changes made to safe repo to be a vulnerable repo.
    The returned snippet is a string containing the diff information.
    Args:
        :pram function_index: The function index to get the diff for.
    Returns:
        :return: The diff snippet for the given function index.
    """
    global PeekDiffSkillGlobal
    PeekDiffSkillGlobal.get_diff(function_index)



class PeekDiffSkill:
    def __init__(self, **kwargs):
        self.func_resolver = kwargs["func_resolver"]
        self.changed_func_resolver = kwargs["changed_func_resolver"]
        self.diff_file = kwargs["diff_file"]
        global PeekDiffSkillGlobal
        PeekDiffSkillGlobal = self

    def get_diff(self, function_index: str, bot=True):
        with open(self.diff_file, "r") as f:
            diff_text = f.read()

        # path = str(self.func_resolver.get_focus_repo_relative_path(function_index))
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
                return tool_error(f"THE CODE OF  `{name}` WAS NOT CHANGED IN THE DIFF FILE")
            else:
                return f"THE CODE OF  `{name}` WAS NOT CHANGED IN THE DIFF FILE"
        else:
            log.info("Found diff for function %s in file %s" % (name, path))
            if bot == True:
                return tool_success(ALL_TEXT)
            else:
                return ALL_TEXT



