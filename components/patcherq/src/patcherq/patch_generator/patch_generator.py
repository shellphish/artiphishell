

import subprocess
import os
import tempfile 
import shutil 
import logging
import hashlib
import yaml

from typing import Any, Tuple, List, Type, NamedTuple
from pathlib import Path
from typing import List

from enum import Enum
import Levenshtein

from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.symbols import SourceLocation
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY, FunctionIndex
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata

from .exceptions import PatchIsDuplicate, IncorrectFilePathException, WrongPatchLocationException, IllegalPatchLocationException, PatchFailedSanitization
from .patch_cache import PatchCache

from ..config import Config

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class PatchEdit(NamedTuple):
    """
    A PatchEdit is a change in the source code that is applied to a file.
    """
    original_file_path: Path
    patched_file_path: Path
    id: str
    original_code: str
    patched_code: str
    start_line: int
    end_line: int

class PatchGenerator:
    '''
    This class is responsible for extracting the patch for the source code
    from the LLM output and applying it to the source code.
    Currently, we are using search-replace to apply the patch. 
    This class output the git_diff that needs to be applied to the original project
    to resolve the bug. 
    NOTE: The only state stored in the class is the current cp we are working on (self.cp)
    '''
    def __init__(self, cp, func_resolver, all_args):

        self.use_task_service = os.getenv('LOCAL_RUN') != 'True'
    
        self.all_args = all_args

        with open(all_args['project_yaml'], 'r') as f:
            self.project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))

        # NOTE: This is the ****UN-BUILT**** ****ORIGINAL***** ChallengeProject!
        self.cp = cp
        self.func_resolver = func_resolver

        self.forbidden_patch_functions = dict()
        # NOTE: this is a dictionary where the key is the forbidden patching location
        #       and the value is a string we are returning to the LLM as a reason why we cannot patch it.
        # ======== LIST OF FORBIDDEN PATCH LOCATIONS ========
        self.forbidden_patch_functions['LLVMFuzzer'] = "You are trying to modify the harness function used to fuzz the program. Your patch CAN NOT IN ANY WAY CHANGE THIS FUNCTION! Please try again with a different patching strategy."
        self.forbidden_patch_functions['fuzzerTest'] = "You are trying to modify the harness function used to fuzz the program. Your patch CAN NOT IN ANY WAY CHANGE THIS FUNCTION! Please try again with a different patching strategy."
        # ===================================================
        
        self.forbidden_patch_files = dict()
        # NOTE: this is a dictionary where the key is the forbidden patching location (file names)
        #       and the value is a string we are returning to the LLM as a reason why we cannot patch it.
        # ======== LIST OF FORBIDDEN PATCH LOCATIONS ========
        self.forbidden_patch_files['fuzz'] = "You are trying to modify one of the harness file that is used to fuzz the program. Your patch CAN NOT IN ANY WAY CHANGE THIS FILE! Please try again with a different patching strategy."
        # ===================================================
        
        # This will store all the patch attempts made by pQ across multiple agents
        self.patch_cache = PatchCache()

    def generate_git_diffs(self, new_cp, file_diffing):
        """
        Generate a Git diff between two files.
        Parameters:
        - file1 (str): Path to the original file (buggy).
        - file2 (str): Path to the patched file (fixed).
        
        Returns:
        - str: The diff output in Git format.
        """
        tfile = Path(tempfile.mktemp(prefix="patch."))
        tfile.touch()

        with tfile.open('w') as output_file:
            result = subprocess.run(
                ["git", "diff", "--no-index", self.cp.project_source, new_cp.project_source],
                stdout=output_file,
                stderr=subprocess.PIPE,  # Capture any error messages if needed
                check=False  # Do not raise an exception for non-zero exit codes
            )

        # Tweaking the diff to remove the unnecessary root
        # NOTE: all the patches are ALWAYS relative to the source-root.
        src_prefix_to_replace = "a" + str(self.cp.project_source)
        dst_prefix_to_replace = "b" + str(new_cp.project_source)

        git_diff = tfile.read_text()
        git_diff = git_diff.replace(src_prefix_to_replace, "a")
        git_diff = git_diff.replace(dst_prefix_to_replace, "b")

        return git_diff

    def get_fresh_repo(self):
        # Create the directory structure for the new project
        new_folder = tempfile.mkdtemp(dir=f"/shared/patcherq/{self.all_args['project_id']}/")
        new_oss_fuzz_dir = os.path.join(new_folder, "oss-fuzz", "projects", self.cp.project_name)
        new_source_dir = os.path.join(new_folder, "source-root")
        os.makedirs(new_source_dir, exist_ok=True)
        os.makedirs(new_oss_fuzz_dir, exist_ok=True)

        # Now copy the source to the new temporary folder
        # NOTE: These copies are always done from an ****UN-BUILT**** Challenge Project, thus there 
        #       is no need of wiping the artifacts folder.
        subprocess.check_call(["cp", "-a", f"{self.cp.project_path}/.", new_oss_fuzz_dir])
        subprocess.check_call(["cp", "-a", f"{self.cp.project_source}/.", new_source_dir])

        # This is the new ChallengeProject object that we are 
        # gonna use to apply the patch
        # NOTE: we don't have to build the container here, we are gonna use the images of the 
        # original challenge project (self.cp)
        return OSSFuzzProject(
                              project_id = self.all_args['project_id'],
                              oss_fuzz_project_path=Path(new_oss_fuzz_dir),
                              augmented_metadata=self.project_yaml,
                              project_source=Path(new_source_dir),
                              use_task_service=self.use_task_service
                             )

    def fuzzy_search(self, X: str, Y: str, min_len: int = None, max_len: int = None) -> Tuple[str, int] | Tuple[None, None]:
        """
        Search for the buggy code in the file in a fuzzy way using Levenshtein distance
        and added distance approximation based on length difference of code snippets.
        """
        if X == Y:
            return X, 0

        min_distance = float('inf')
        best_substring = ''
        X_length = len(X)
        min_len = min_len or int(X_length * 0.8)
        max_len = max_len or int(X_length * 1.2)
        
        for length in range(min_len, max_len + 1):
            for i in range(len(Y) - length + 1):
                substring = Y[i:i+length]
                distance = Levenshtein.distance(X, substring)
                if distance < min_distance:
                    min_distance = distance
                    best_substring = substring
        return best_substring if best_substring else None, min_distance if best_substring else None

    def sanitize_code_edit(self, edit:PatchEdit) -> Tuple[bool, PatchEdit, str]:
        # 🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️🙅🏻‍♂️
        # Checking for bad edits 
        # 1- patching LLVMFuzzerOneInput
        # @returns:
        #  - (True, edit, reason ) If the edit is ok. edit could be a "rebased" edit.
        #  - (False, None, reason ) If the edit is to be discarded (e.g., it was illegal and we could not find a good location), reason is the reason why we discarded it.
        # ================================================================
        function_attempted_to_patch_key = None
        
        edit_file = os.path.basename(edit.original_file_path)
        edit_start_line = edit.start_line

        # Grab all the functions in the file the LLM wants to patch
        all_funcs_in_patched_file_keys:List[FUNCTION_INDEX_KEY] = list(self.func_resolver.find_by_filename(edit_file))
        
        # Look for the exact function the LLM wants to patch given the start line of the edit.
        for func_in_patched_file_key in all_funcs_in_patched_file_keys:
            func_boundaries = self.func_resolver.get_function_boundary(func_in_patched_file_key)
            # If the boundaries are within this functions, we found the function!
            if edit_start_line >= func_boundaries[0] and edit_start_line <= func_boundaries[1]:
                function_attempted_to_patch_key = func_in_patched_file_key
                break

        if function_attempted_to_patch_key == None:
            # It could be the LLM is attempting to patch a header file or something else
            # In those cases, we don't really have a function object back...
            # Let this change pass the sanitization for now.
            return True, edit, "Modifying code out of a function"
        
        function_attempted_to_patch_obj:FunctionIndex = self.func_resolver.get(function_attempted_to_patch_key)
        
        
        # Check 1: Are we patching at any forbidden locations?
        for forbidden_patch_function in self.forbidden_patch_functions.keys():
            if forbidden_patch_function in function_attempted_to_patch_obj.funcname:
                # If the function is in the forbidden patch functions, abort the patching process
                logger.info("🙅🏻‍♂️ Patching attempt contains forbidden function: %s.", function_attempted_to_patch_obj.funcname)
                reason = self.forbidden_patch_functions[forbidden_patch_function]
                # NOTE: For now, I want to completely reject patches that are touching the forbidden functions
                # such as LLVMFuzzerOneInput.
                # This might change in the future, but for now, let's keep it simple.
                raise IllegalPatchLocationException(reason)

        # Check 2: Are we patching at any forbidden files location?
        # for forbidden_patch_file in self.forbidden_patch_files.keys():
        #     # NOTE: naive check, we are just checking if the file name contains the forbidden patch file (i.e., "fuzz")
        #     if forbidden_patch_file in str(function_attempted_to_patch_obj.target_container_path):
        #         # If the function is in the forbidden patch functions, abort the patching process
        #         logger.info("🙅🏻‍♂️ Patching attempt contains forbidden file: %s.", function_attempted_to_patch_obj.funcname)
        #         reason = self.forbidden_patch_files[forbidden_patch_file]
        #         # NOTE: For now, I want to completely reject patches that are touching files in a path
        #         # that contains the forbidden patch file (i.e., "fuzz").
        #         # This might change in the future, but for now, let's keep it simple.
        #         raise IllegalPatchLocationException(reason)

        # All good, the edit looks fine!
        return True, edit, "The patch edit is valid and can be applied as it is"

    def is_patch_duplicate(self, patch_attempt: dict) -> Tuple[bool, Any, str]:
        patch_hash = hashlib.sha256(str(patch_attempt).encode()).hexdigest()
        if self.patch_cache.has(patch_hash):
            logger.info(' ⚠️ Duplicate patch detected\n')
            action = self.patch_cache.get_action(patch_hash)
            return True, action, patch_hash
        else:
            return False, None, None

    def __sanitize_file_path(self, file_path:str):
        # Making sure that the file_path is relative!
        # This path is ALWAYS relative to the source-root
        file_path = file_path.lstrip('/')

        # Get the file with the function resolver
        # NOTE: this check ensures that the LLM did not hallucinate a name
        functions_info = list(self.func_resolver.find_by_filename(file_path))

        if len(functions_info) != 0:
            functions_in_scope = []
            for func_key in functions_info:
                func_index:FunctionIndex = self.func_resolver.get(func_key)
                if func_index.focus_repo_relative_path:
                    functions_in_scope.append(func_key)
                    # We can just stop here since we found at least one function in scope in this file
                    break

            # NOTE: the file_path is relative to the focused repo.
            file_path = str(self.func_resolver.get(functions_in_scope[0]).focus_repo_relative_path).lstrip("/")
        else:
            # Maybe that is a .h that we do not have in the function resolver?
            # FIXME: recover from this, we can get the basename and do a find to see if that file
            # exists in the focused repo path.
            # FIXME: we might want to allow only to specific type of files here.
            # results = find('/focus/report/path', name=os.path.basename(file_path), type='f')
            logger.info("🫡 Cannot find the file in the function resolver, using the file path as it is.")

        return file_path
    
    def run(self, patch_attempt: dict):

        # Check if the patch is a duplicate
        is_dup, action, patch_hash = self.is_patch_duplicate(patch_attempt)
        if is_dup:
            # If the patch is a duplicate, we are gonna replay 
            # whatever we did last time!
            raise PatchIsDuplicate(action, patch_hash)

        # We are storing the file diffing for later
        file_diffing = []

        # Make a copy of the original ChallengeProject object
        # (so we can modify it and generate the git diff)
        new_cp = self.get_fresh_repo()

        # Here we want to apply the patch to the source code 
        cp_src = self.cp.project_source
        new_cp_src = new_cp.project_source

        # =================================
        # First we group-by changes by file
        # =================================
        changes_by_file = {}
        for change in patch_attempt:

            file_path = self.__sanitize_file_path(change['file'])
            change['file'] = file_path

            original_file_path = cp_src / Path(change['file'])
            if not original_file_path.exists():
                raise IncorrectFilePathException(original_file_path, f"The file {original_file_path} provided in the patch does not exist.")
            
            if original_file_path not in changes_by_file.keys():
                changes_by_file[original_file_path] = []
            
            # Create the PatchEdit object

            # Before, some consistency check to avoid corrupted patches...
            # 1) Is the first line of the original code matching the <start> line?
            proposed_start_line = change['line']['start']
            proposed_original_code = change['original']

            proposed_original_code_first_line = proposed_original_code.split('\n')[0]
            
            # @degrigis, May 1st
            proposed_original_code_first_line = proposed_original_code_first_line.strip()

            # Open the original file path
            with open(original_file_path, 'r') as f:
                original_file_content = f.readlines()
            
            try:
                original_code_at_proposed_line = original_file_content[proposed_start_line-1] # -1 because the line numbers are 1-based
            except IndexError:
                logger.critical("❌ The proposed start line %s is out of bounds for the file %s.", proposed_start_line, original_file_path)
                reason = f"That is an invalid patch because the proposed start line {proposed_start_line} is out of bounds for the file {original_file_path}, you MUST fix that.\n"
                raise WrongPatchLocationException(reason)

            # @degrigis, May 1st
            original_code_at_proposed_line = original_code_at_proposed_line.strip()

            res, distance = self.fuzzy_search(proposed_original_code_first_line, original_code_at_proposed_line)

            # NOTE: distance > 1 takes into account the fact that the original code might have 
            # some trailing whitespace. In other words, we tolerate a distance=1.
            if res is None or distance is None or distance > 1:
                # The original code snippet does not match the original code at the proposed start line
                # This is an imprecise patch, we must fix it!
                logger.info("⚠️ Imprecise patch detected! The proposed start line does not match with the actual original code. Recovering...")
                logger.info(" - Proposed start line: %s", proposed_start_line)
                logger.info(" - Proposed original code: %s", proposed_original_code_first_line)
                logger.info(" - Original code at proposed start line: %s", original_code_at_proposed_line)

                # Most of the time, it is just an off-by-one error in the line number
                # We can fix it by searching for the original code snippet in the file

                # NOTE: If the fuzzy search fails, we are just gonna abort immediately 
                #       and ask the llm to fix it.
                try:
                    res, distance = self.fuzzy_search(proposed_original_code_first_line, original_file_content[proposed_start_line].strip())
                except Exception as e:
                    logger.info("  ❌ Unable to automatically recover from the imprecise patch! Looping back to the ProgrammerGuy.")
                    reason =  "The original code snippet you used in the report does not match the original code at the proposed start line\n"
                    reason += f'Specifically, you told us that the first line of the original code at line {proposed_start_line} was ```{proposed_original_code_first_line}``` but instead we found ```{original_code_at_proposed_line}```'
                    reason += "Please, double check the line number and the original code snippet and fix the patch attempt."
                    raise WrongPatchLocationException(reason)
                
                # Did the LLM meant the line after?
                if distance is not None and distance <= 1:
                    # Yep!
                    logger.info("  ✅ Recovering: from off-by-one error in the line number, changing the start line with %d", proposed_start_line + 1)
                    change['line']['start'] = proposed_start_line + 1
                else:
                    # Maybe the line before?
                    res, distance = self.fuzzy_search(proposed_original_code_first_line, original_file_content[proposed_start_line-2].strip())
                    if distance is not None and distance <=1:
                        logger.info("  ✅ Recovering: from off-by-one error in the line number, changing the start line with %d", proposed_start_line - 1)
                        change['line']['start'] = proposed_start_line - 1
                    else:
                        logger.info("  ❌ Unable to automatically recover from the imprecise patch! Looping back to the ProgrammerGuy.")
                        reason =  "The original code snippet you used in the report does not match the original code at the proposed start line\n"
                        reason += f'Specifically, you told us that the first line of the original code at line {proposed_start_line} was ```{proposed_original_code_first_line}``` but instead we found ```{original_code_at_proposed_line}```'
                        reason += "Please, double check the line number and the original code snippet and fix the patch attempt."
                        raise WrongPatchLocationException(reason)
            else:
                logger.info(" ✅ Patch is consistent with the original code at the proposed start line")

            change = PatchEdit(
                # This is the change id
                id=int(change['change_id'])+1,
                # This is the original file path (buggy)
                original_file_path=original_file_path,
                # This is where the patched file will be saved
                patched_file_path= new_cp_src / Path(change['file']),
                # This is the line range where the change will be applied
                start_line=change['line']['start'],
                end_line=change['line']['start'] + len(change['original'].split('\n')) - 1,
                # This is the original code snippet that we want to replace
                original_code=change['original'],
                # This is the patched code snippet
                patched_code=change['patched']
            )
            changes_by_file[original_file_path].append(change)

        # Sanitize every change!
        logger.info(" 🧼 Sanitizing all the code edits!")
        sanitized_changes_by_file = {k:list() for k in changes_by_file.keys()}
        sanitization_warnings = []
        for file_path, patch_edits in changes_by_file.items():
            # Sanitize every edit in this file
            for edit in patch_edits:
                res, new_edit, reason = self.sanitize_code_edit(edit)
                if res:
                    sanitized_changes_by_file[file_path].append(new_edit)
                else:
                    logger.warning(" 🚮 Discarding this edit %s from the attempted patch...", edit)
                    sanitization_warnings.append(reason)

        # Do we have edits left? 😅
        if len(sanitized_changes_by_file) == 0:
            # LOL, we discarded everything, let's tell the LLM
            errors = "\n".join(sanitization_warnings)
            raise PatchFailedSanitization(errors)
        
        # Did we maintain all the edits?
        if len(sanitized_changes_by_file) == len(changes_by_file):
            logger.info("   ✅ All code edits passed the sanitization checks!")
        else:
            # We lost some edits during the sanitization process, let's inform the user
            logger.warning("   ⚠️ Some code edits were discarded during sanitization. This may lead to an incomplete patch.")
            logger.warning("    Original number of edits: %d", len(changes_by_file))
            logger.warning("    Sanitized number of edits: %d", len(sanitized_changes_by_file))
            logger.warning("    This is not FATAL, we are attempting this patch nonetheless")

        # =========================
        # Now we apply the changes!
        # =========================
        for file_path, patch_edits in sanitized_changes_by_file.items():
            logger.info("👨🏻‍🔧 Fixing buggy file: %s", file_path)

            # Open the original file content
            with open(file_path, 'r') as f:
                curr_file_lines = f.readlines()
            updated_file_content = ''

            # Apply changes for all the patch_edit for this file in order
            sorted_patch_edits = sorted(patch_edits, key=lambda x: x.start_line)
            prev_end_line = 0
            for change in sorted_patch_edits:
                logger.info(" - 🛠️ Applying change to %s", change.patched_file_path)
                updated_file_content += ''.join(curr_file_lines[prev_end_line:change.start_line-1]) + change.patched_code + '\n'
                prev_end_line = change.end_line
            updated_file_content += ''.join(curr_file_lines[prev_end_line:])
            logger.info("✅ Done applying changes to %s", change.patched_file_path)

            # Write the new curr_file_content to the patched file destination
            with open(change.patched_file_path, 'w') as f:
                f.write(updated_file_content)
    
            # Register the edits for later if we want to generate a git diff
            logger.info("Original file: %s", change.original_file_path)
            logger.info("Patched file: %s", change.patched_file_path)
            file_diffing.append((change.original_file_path, change.patched_file_path))
        
        return self.generate_git_diffs(new_cp, file_diffing), patch_attempt, self.functions_in_patch(patch_attempt)

    def functions_in_patch(self, patch_attempt: dict) -> List[str]:
        functions_attempted_to_patch=set()
        for patch_edits in patch_attempt:
            patched_file = patch_edits['file']
            patched_lines = patch_edits['line']
            patched_boundaries = (patched_lines['start'], patched_lines['end'])
            all_funcs_in_patched_file = list(self.func_resolver.find_by_filename(patched_file))
            # all_funcs_in_patched_file are FUNCTION_INDEX_KEYs
            for func_in_patched_file in all_funcs_in_patched_file:
                func_boundaries = self.func_resolver.get_function_boundary(func_in_patched_file)
                # If the boundaries are within this functions, we found the function!
                if patched_boundaries[0] >= func_boundaries[0] and patched_boundaries[1] <= func_boundaries[1]:
                    functions_attempted_to_patch.add(self.func_resolver.get(func_in_patched_file).funcname)
                    # we found the function, check the next patch edit
                    break
        functions_attempted_to_patch = list(functions_attempted_to_patch)
        logger.info('Functions attempted to patch: %s', functions_attempted_to_patch)
        return functions_attempted_to_patch
