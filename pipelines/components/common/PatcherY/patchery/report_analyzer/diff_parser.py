from patchery.data import ProgramPOI, ProgramInfo
from patchery.code_parsing import CodeParser
from patchery.code_parsing.code_function import CodeFunction
from patchery.code_parsing.code_parser_backend import CodeParserBackend
from patchery.utils import absolute_path_finder, read_src_from_file
from pathlib import Path
from typing import Optional, Dict, List

import logging
import git
import os
import re
import json

_l = logging.getLogger(__name__)


# class DiffCodeParser(CodeParser):
#     def __init__(self, code_file: Path, source_root: Path, commit: str, lang="C"):
#         super().__init__(code_file, lang)
#         self.source_root = Path(source_root).resolve()
#         self.repo = git.Repo(self.source_root)
#         self.commit_hash = commit
#         self.commit = self.repo.commit(commit)
#         self.relative_file = code_file.relative_to(self.source_root)
#         # self.code_file =self.commit.tree / str(self.relative_file)
#         self.code_file = code_file

#     def parse(self):
#         self.repo.git.checkout(self.commit_hash)
#         super().parse()
#         latest_commit = self.repo.head.commit.hexsha
#         self.repo.git.checkout(latest_commit)


class DiffParser:
    def __init__(
        self,
        prog_info: ProgramInfo,
        crash_commit: str,
        indices_by_commits: Path,
        changed_func_json_dir_by_commits: Path,
        indices: Path,
        func_json_dir: Path,
    ):

        self.src_root = Path(prog_info.source_root).resolve()
        self.repo = git.Repo(self.src_root)
        self.prog_info = prog_info
        self.commit_hash = crash_commit
        try:
            self.crash_commit = self.repo.commit(crash_commit)
        except git.BadName:
            _l.warning(f"Commit {crash_commit} does not exist.")
        self.crash_parent_commit = self._get_immediate_parent_commit()

        self.indices_by_commit = indices_by_commits
        self.changed_func_info_dir = changed_func_json_dir_by_commits
        self.indices = indices
        self.func_json_dir = func_json_dir
        self.mapping_dict = {}

    def get_diff(self) -> Optional[str]:
        # return self.crash_commit.diff(self.crash_parent_commit, create_patch=True)
        return self.crash_parent_commit.diff(self.crash_commit, create_patch=True)

    ##### Step 1 #####
    # Extract filename, line number and diff text for every diff piece
    def extract_pois_diff(self) -> List[Dict]:

        diffs = self.get_diff()
        file_line_diff = []
        pattern = r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@"
        # pattern = r'@@ -(\d+) \+(\d+) @@'
        for diff in diffs:
            # we skip any time a file is deleted or created
            if diff.a_blob is None or diff.b_blob is None:
                continue

            diff_text = diff.diff.decode("utf-8")
            diff_slices = diff_text.split("\n")

            matching_indices = []
            linenums = []
            for i, string in enumerate(diff_slices):
                match = re.search(pattern, string)
                if match:
                    matching_indices.append(i)
                    line_number_after = int(match.group(2))
                    linenums.append(line_number_after)
                    match = False

            for i, match in enumerate(matching_indices):
                if i < len(matching_indices) - 1:
                    diff_body = "\n".join(diff_slices[match : matching_indices[i + 1]])
                else:
                    diff_body = "\n".join(diff_slices[matching_indices[i] :])

                file_line_diff.append(
                    {
                        "filename": diff.b_path,
                        "line": linenums[i],
                        "git_diff": diff_body,
                    }
                )
        return file_line_diff

    #### Step 2 ####
    # After getting diff info by running self.exitract_poi_diff()
    # Go to clang_indexers output by commit and check which function the diff piece belong to by compare line number
    # Once we find the function, save the json file name and group diff piece by the function they belong to
    def find_func_from_json_by_commits(self):
        if not self.changed_func_info_dir:
            _l.critical(f"Must provide a function info jsons by commits. Or we cannot construct POIs for commit diff!")
        commit_dirs = os.listdir(self.changed_func_info_dir / self.src_root.name)
        for commit_dir in commit_dirs:
            commit = str(commit_dir).split("_")[-1]
            if commit.startswith(self.commit_hash):
                crash_dir = self.changed_func_info_dir / self.src_root.name / commit_dir
                break

        func_dir = Path(crash_dir)
        func_files = list(func_dir.rglob("*.json"))
        diff_dict = self.extract_pois_diff()
        for diff in diff_dict:
            linenum = diff["line"]
            filename = Path(diff["filename"]).name
            diff_piece = diff["git_diff"]
            for func_file in func_files:
                if filename in func_file.name:
                    with open(func_file) as f:
                        data = json.load(f)
                        # assert data["filename"] == filename
                        if int(data["start_line"]) <= linenum and int(data["end_line"]) >= linenum:
                            commit_func_json_name = func_file.name
                            func_sig = data["signature"]
                            if func_sig not in self.mapping_dict:
                                self.mapping_dict[func_sig] = {
                                    "diff": diff_piece,
                                    "json_file": commit_func_json_name,
                                    "filename": data["filepath"],
                                    "funcname": data["funcname"],
                                    "filesig": None,
                                    "latest_commit_jsonfile": None,
                                }
                            else:
                                index = diff_piece.find("@")
                                self.mapping_dict[func_sig]["diff"] += "\n" + diff_piece[index:]
                            break

    #### Step 3 ####
    # After getting the json file name, go to the indices by commits to match the file name back to the key_index
    # From the key_index extract the filename and function signature.
    # The combinationo of filename and function signature is a unique identifier that can help us find the same function in any commit

    def find_index_by_commit(self):
        if not self.indices_by_commit:
            _l.warning(
                f"You do not provide indices_by_commit json file. Cannot access function info of different commits"
            )
            return
        try:
            with open(self.indices_by_commit) as f:
                commit_func_indices = json.load(f)
        except FileNotFoundError:
            _l.warning(f"Cannot access file indices_by_commit file {self.indices_by_commit}")
        crash_indices = {}
        commit_func_indices = commit_func_indices[str(self.src_root.name)]
        for k, v in commit_func_indices.items():
            commit = k.split("_")[-1]
            if commit.startswith(self.commit_hash):
                crash_indices = v
                break
        if len(crash_indices) < 1:
            _l.warning(f"Crash_indices not found. Something is wrong")
        for sig, diff in self.mapping_dict.items():
            for k, v in crash_indices.items():
                if Path(v).name == diff["json_file"]:
                    key = k
                    key_info = key.split(":")
                    file_name = key_info[0]
                    file_sig = key_info[-1]
                    diff["filename"] = file_name
                    diff["filesig"] = file_sig
                    break

    #### Step 4 ####
    # After getting filename and signature combination, go to the function indices (which is by default latest commit)
    # And find the key index by mapping the filename and function signature
    # After we find the mapped key_index, we can read the json file name
    def find_latest_json_file(self):
        if not self.indices:
            _l.warning(f"You do not provide function indices.")
            return
        try:
            with open(self.indices) as f:
                indices = json.load(f)
        except FileNotFoundError:
            _l.warning(f"Cannot access function indices file {self.indices}")
        for k, v in self.mapping_dict.items():
            for key, fi in indices.items():
                if key.startswith(v["filename"]) and key.endswith(v["filesig"]):
                    v["latest_commit_jsonfile"] = fi
                    break

    # After getting the json file name, we can read the json file and extract the function info from it and contruct POIs
    def retrieve_pois(self):
        self.find_func_from_json_by_commits()
        self.find_index_by_commit()
        self.find_latest_json_file()
        new_pois = []

        for k, v in self.mapping_dict.items():
            global_variables = []
            func_startline = None
            func_endline = None
            source_code = None
            if v.get("latest_commit_jsonfile"):
                absolute_json_path = self.func_json_dir / v["latest_commit_jsonfile"]
                with open(absolute_json_path, "r") as f:
                    func_info = json.load(f)
                source_code_backup = func_info["code"]
                funcname = func_info["funcname"]
                global_variables_dict = func_info["global_variables"]
                for g_dict in global_variables_dict:
                    global_variables.append(g_dict.get("declaration"))
                func_startline = func_info["start_line"]
                func_endline = func_info["end_line"]
                filepath = func_info["filepath"]
                source_code = read_src_from_file(filepath, func_startline, func_endline, backup_code=source_code_backup)
            else:
                filepath = v.get("filename")
                funcname = v.get("funcname")
            git_diff = v["diff"]
            if not filepath:
                _l.critical(f"Could not resolve the filepath for a commit, this POI is lost on {funcname}!")
                continue

            new_pois.append(
                ProgramPOI(
                    filepath,
                    funcname,
                    git_diff=git_diff,
                    global_variables=global_variables,
                    func_src=source_code,
                    func_startline=func_startline,
                    func_endline=func_endline,
                )
            )

        return new_pois

    def _get_immediate_parent_commit(self):
        parents = self.crash_commit.parents
        if parents:
            return parents[0]
        return None
