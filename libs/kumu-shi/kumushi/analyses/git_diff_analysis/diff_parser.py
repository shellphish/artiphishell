from pathlib import Path
from typing import Dict, List
import logging


import git
from kumushi.data.program import Program
from kumushi.data.poi import PoI, PoISource, CodeFunction, PoICluster
import unidiff
from shellphish_crs_utils.function_resolver import LocalFunctionResolver

_l = logging.getLogger(__name__)


class DiffParser:
    def __init__(
            self,
            program: Program,
            commit_function_resolver: LocalFunctionResolver,
            local_run: bool = False,
            project_name: str = None,
    ):

        self.src_root = Path(program.source_root).resolve()
        self.repo = git.Repo(self.src_root)
        self.prog_info = program
        self.commit_hash = self.repo.head.commit.hexsha
        try:
            self.crash_commit = self.repo.commit(self.commit_hash)
        except git.BadName:
            _l.warning(f"Commit {self.commit_hash} does not exist.")
            self.crash_commit = None
        self.commit_function_resolver = commit_function_resolver
        self.local_run = local_run
        self.project_name = project_name
        self.mapping_dict = {}

    def get_function_diff(self, func_name) -> str:
        """
        Get the diff of a function by its name.
        """
        diff_text = self.repo.git.diff('-w', '--ignore-blank-lines', self.crash_commit.parents[0].hexsha, self.commit_hash)
        patch_set = unidiff.PatchSet.from_string(diff_text)
        all_diff = []
        for patch in patch_set:
            for hunk in patch:
                if func_name in hunk.section_header:
                    all_diff.append(''.join([str(line) for line in hunk.copy()]))
        return ''.join(all_diff)

    def get_all_changed_funcs(self) -> List[PoI]:
        diff_pois = []
        _l.info(f"Retrieving all changed functions {len(self.commit_function_resolver.keys())}")
        for function_index in self.commit_function_resolver.keys():
            poi = self.load_function(function_index)
            if poi is not None:
                diff_pois.append(poi)
        return diff_pois

    def load_function(self, index: str) -> PoI | None:
        try:
            #FIXME: Mismatch between names
            function_content = self.prog_info.code._function_resolver.get(index)
        except Exception as e:
            _l.error(f"Failed to load function {index}. Error: {e}")
            return None
        name = function_content.funcname
        start_line = function_content.start_line
        end_line = function_content.end_line
        focus_repo_relative_path = function_content.focus_repo_relative_path
        if focus_repo_relative_path is None:
            return None
        code = function_content.code
        global_vars = function_content.global_variables
        code_function = CodeFunction(name, start_line, end_line, focus_repo_relative_path,
                                     code=code, global_vars=global_vars)
        poi = PoI(function=code_function, sources=[PoISource.COMMIT],
                  git_diff=self.get_function_diff(code_function.name))
        return poi

    # After getting the json file name, we can read the json file and extract the function info from it and contruct POIs
    def retrieve_pois(self) -> list[PoICluster]:
        if self.crash_commit is None or len(self.crash_commit.parents) == 0:
            _l.error(f"Commit {self.commit_hash} is the initial commit. Cannot find parent commit.")
            return []
        diff_pois = self.get_all_changed_funcs()
        for poi in diff_pois:
            poi.source = PoISource.COMMIT
        clusters = [PoICluster.from_pois([p], source=PoISource.COMMIT) for p in diff_pois]
        _l.info(f"Found {len(diff_pois)} pois")
        return clusters
