import hashlib
from abc import ABC, abstractmethod

from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import json
import threading
import jq
import sys
import logging
import re
import shutil
import subprocess
import tempfile
import requests
import os
from pathlib import Path
import time
from typing import Dict, Iterator, List, Optional, Tuple, Union, Literal
from shellphish_crs_utils.models.constraints import PDT_ID
from shellphish_crs_utils.models.symbols import RelativePathKind, SourceLocation
from shellphish_crs_utils.models.indexer import FunctionIndex, CommitToFunctionIndex, FUNCTION_INDEX_KEY
from shellphish_crs_utils.models.coverage import CoverageLine, FunctionCoverage, LinesCoverage, FunctionCoverageMap, FileCoverageMap
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
import yaml

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

class MatchKind(Enum):
    DEFINITELY = 1
    MAYBE = 2
    DEFINITELY_NOT_IN_WELL_BEHAVED_SETTINGS = 3 # heck you sqlite3

@dataclass
class FunctionIndexRanking:
    match_kind: MatchKind
    match_value: float

# for context, we hardcode sqlite3.c here to be compatible with the sqlite3 amalgamation. We should probably be okay with the ranking
# even without this customization, but it helps to be sure for a target we know is likely involved

def get_function_name_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    if not source_location.function_name:
        return None
    if source_location.function_name == function_index_entry.funcname:
        return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
    if source_location.function_name.startswith('OSS_FUZZ_') and source_location.function_name[len('OSS_FUZZ_'):] == function_index_entry.funcname:
        # special case function prefixes of OSS_FUZZ_ as e.g., used in libpng
        return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
    if source_location.function_name.endswith('::' + function_index_entry.funcname) or source_location.function_name.endswith('.' + function_index_entry.funcname):
        return FunctionIndexRanking(MatchKind.MAYBE, 0.8)
    if function_index_entry.funcname.endswith('::' + source_location.function_name) or function_index_entry.funcname.endswith('.' + source_location.function_name):
        return FunctionIndexRanking(MatchKind.MAYBE, 0.8)
    if function_index_entry.funcname in source_location.function_name:
        return FunctionIndexRanking(MatchKind.MAYBE, 0.6)
    if source_location.function_name in function_index_entry.funcname:
        char_before = source_location.function_name.index(function_index_entry.funcname) - 1
        char_after = char_before + len(function_index_entry.funcname)
        char_before = function_index_entry.funcname[char_before] if char_before >= 0 else ' '
        char_after = function_index_entry.funcname[char_after] if char_after < len(function_index_entry.funcname) else ' '
        if char_before in ['_', ' ', ':', '.'] and char_after in ['_', ' ', ':', '.']:
            # underscores are a last resort for stuff like OSS_FUZZ_libpng_read_row and should be ranked lower than non-underscore matches
            return FunctionIndexRanking(MatchKind.MAYBE, 0.4 if char_before != '_' and char_after != '_' else 0.3)
    elif function_index_entry.funcname in source_location.function_name:
        char_before = function_index_entry.funcname.index(source_location.function_name) - 1
        char_after = char_before + len(source_location.function_name)
        char_before = source_location.function_name[char_before] if char_before >= 0 else ' '
        char_after = source_location.function_name[char_after] if char_after < len(source_location.function_name) else ' '
        if char_before in ['_', ' ', ':', '.'] and char_after in ['_', ' ', ':', '.']:
            return FunctionIndexRanking(MatchKind.MAYBE, 0.4 if char_before != '_' and char_after != '_' else 0.3)

    if function_index_entry.funcname in source_location.function_name or source_location.function_name in function_index_entry.funcname:
        # if it's included in ANY way possible, it is at least a bit more of a match than no match, but only barely
        return FunctionIndexRanking(MatchKind.MAYBE, 0.1)

    return FunctionIndexRanking(MatchKind.DEFINITELY_NOT_IN_WELL_BEHAVED_SETTINGS, 0.0)

def count_matching_final_path_parts(path_a, path_b):
    parts_a = path_a.parts
    parts_b = path_b.parts
    count = 0
    for i, (part_a, part_b) in enumerate(zip(reversed(parts_a), reversed(parts_b))):
        if part_a == part_b:
            count += 1
        else:
            break
    return count, min(len(parts_a), len(parts_b))

def get_relative_filename_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    if source_location.focus_repo_relative_path and function_index_entry.focus_repo_relative_path and source_location.focus_repo_relative_path == function_index_entry.focus_repo_relative_path:
        return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0) # if the focus repo relative path is the same, we have a perfect match
    if source_location.relative_path:
        if source_location.relative_path.name == 'sqlite3.c': # fork the amalgamation, holy shirt
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)

        if function_index_entry.focus_repo_relative_path and source_location.relative_path == function_index_entry.focus_repo_relative_path:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        if str(function_index_entry.target_container_path).endswith(str(source_location.relative_path)):
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        # if function_index_entry.focus_repo_relative_path and (
        #         str(source_location.relative_path) in str(function_index_entry.focus_repo_relative_path)
        #         or
        #         str(function_index_entry.focus_repo_relative_path) in str(source_location.relative_path)
        #     ):
        #     matching, min_match = count_matching_final_path_parts(source_location.relative_path, function_index_entry.focus_repo_relative_path)
        #     return FunctionIndexRanking(MatchKind.MAYBE, 0.8 * matching / min_match)

        if str(source_location.relative_path) in str(function_index_entry.target_container_path):
            matching, min_match = count_matching_final_path_parts(source_location.relative_path, function_index_entry.target_container_path)
            return FunctionIndexRanking(MatchKind.MAYBE, 0.5 * matching / min_match)

def get_full_file_path_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    if source_location.full_file_path:
        if function_index_entry.target_container_path == source_location.full_file_path:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        if source_location.full_file_path.name == 'sqlite3.c': # fork the amalgamation, holy shirt
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        matching, min_match = count_matching_final_path_parts(source_location.full_file_path, function_index_entry.target_container_path)
        return FunctionIndexRanking(MatchKind.MAYBE, 0.8 * matching / min_match)

def get_filename_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    if source_location.file_name:
        if source_location.file_name == function_index_entry.filename:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        if source_location.file_name == 'sqlite3.c': # fork the amalgamation, holy shirt
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        if function_index_entry.focus_repo_relative_path and source_location.file_name == function_index_entry.focus_repo_relative_path.name:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        if source_location.file_name.name == function_index_entry.target_container_path.name:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)
        return FunctionIndexRanking(MatchKind.DEFINITELY_NOT_IN_WELL_BEHAVED_SETTINGS, 0.0)

def get_line_number_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    if source_location.line_number is not None:
        if source_location.line_number == function_index_entry.start_line:
            return FunctionIndexRanking(MatchKind.DEFINITELY, 1.0)

        # sometimes the first line is a bit off (allow wiggle room of 3 lines)
        if function_index_entry.start_line - 3 <= source_location.line_number <= function_index_entry.start_line + 3:
            return FunctionIndexRanking(MatchKind.MAYBE, 0.8)

        if function_index_entry.start_line - 3 <= source_location.line_number <= function_index_entry.end_line + 3:
            return FunctionIndexRanking(MatchKind.MAYBE, 0.5)

        # line number is so far away that it's almost certainly not the same function in well-behaved apps. *cough* not sqlite3 *cough*
        return FunctionIndexRanking(MatchKind.DEFINITELY_NOT_IN_WELL_BEHAVED_SETTINGS, 0.0)

def get_java_info_match(source_location: SourceLocation, function_index_entry: FunctionIndex) -> Optional[FunctionIndexRanking]:
    matching = 0
    total = 0
    if not source_location.java_info:
        return None
    if source_location.java_info.class_name:
        total += 1
        cur = 0
        if source_location.java_info.class_name + '.java' == function_index_entry.target_container_path.name:
            cur += 1
        if source_location.java_info.class_name == function_index_entry.class_name or function_index_entry.class_name.endswith(source_location.java_info.class_name):
            cur += 1

        class_name_root = function_index_entry.target_container_path.name.split('.java')[0]
        if source_location.java_info.class_name.startswith(class_name_root):
            cur += 0.8 if source_location.java_info.class_name.startswith(class_name_root + '$') else 0.5
        matching += cur / 3

    if source_location.java_info.method_name:
        total += 1
        if source_location.java_info.method_name == function_index_entry.funcname:
            matching += 1

    if source_location.java_info.package:
        total += 1
        if source_location.java_info.package == function_index_entry.package:
            matching += 1

    return FunctionIndexRanking(MatchKind.MAYBE, matching / total) if total > 0 else None

def prepare_for_json(obj):
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: prepare_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [prepare_for_json(v) for v in obj]
    return obj

def function_index_to_source_location(key: FUNCTION_INDEX_KEY, index_obj: FunctionIndex) -> SourceLocation:
    # this is questionable
    return SourceLocation(
        focus_repo_relative_path=index_obj.focus_repo_relative_path,
        function_name=index_obj.funcname,
        line_number=index_obj.start_line,
        raw_signature=index_obj.signature or key.split('::',1)[-1],
        function_index_key=key,
        function_index_signature=key,
        file_name=Path(index_obj.filename),
        full_file_path=key.split(':',1)[0]
    )

class FunctionResolver:
    def __init__(self, focus_repo_container_path: Optional[Path]=None):
        self.cached_code_lines = {}
        self.cached_jq_filter_expression_keys = {}
        self.focus_repo_container_path = focus_repo_container_path
        self.cached_hashes = {}
    
    @abstractmethod
    def is_ready(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_funcname(self, key: FUNCTION_INDEX_KEY) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_focus_repo_relative_path(self, key: FUNCTION_INDEX_KEY) -> Optional[Path]:
        raise NotImplementedError

    @abstractmethod
    def get_target_container_path(self, key: FUNCTION_INDEX_KEY) -> Path:
        raise NotImplementedError

    @abstractmethod
    def get_code(self, key: FUNCTION_INDEX_KEY) -> Tuple[Optional[Path], Path, int, str]:
        raise NotImplementedError

    @abstractmethod
    def get_function_boundary(self, key: FUNCTION_INDEX_KEY) -> Tuple[int, int]:
        raise NotImplementedError

    @abstractmethod
    def _find_matching_indices(self, s: str) -> Iterator[FUNCTION_INDEX_KEY]:
        raise NotImplementedError

    @abstractmethod
    def resolve_with_leniency(self, name: str) -> Iterator[FUNCTION_INDEX_KEY]:
        raise NotImplementedError

    @abstractmethod
    def find_by_funcname(self, s: str) -> Iterator[FUNCTION_INDEX_KEY]:
        raise NotImplementedError

    @abstractmethod
    def find_by_filename(self, s: Union[Path, str]) -> Iterator[FUNCTION_INDEX_KEY]:
        raise NotImplementedError

    @abstractmethod
    def find_matching_indices(
        self,
        indices: List[FUNCTION_INDEX_KEY],
        scope: Literal['all', 'focus', 'non-focus', 'compiled'] = 'focus',
        can_include_self: bool=True,
        can_include_build_generated: bool = True,
    ) -> Tuple[
        Dict[FUNCTION_INDEX_KEY, FUNCTION_INDEX_KEY],
        List[FUNCTION_INDEX_KEY]
    ]:
        """
        For each index:
        Finds the first "other" index which matches the given index.
        For example if given an index from the source directory,
        it can find the matching copy in the build directory
        Returns a dict of the form {index: matching_index}
        and a list of indices that were not found
        """
        raise NotImplementedError

    def find_matching_index(
        self,
        index: FUNCTION_INDEX_KEY,
        scope: Literal['all', 'focus', 'non-focus', 'compiled'] = 'focus',
        can_include_self: bool=True,
        can_include_build_generated: bool = True,
    ) -> Optional[FUNCTION_INDEX_KEY]:
        """
        Finds the first "other" index which matches the given index.
        For example if given an index from the source directory,
        it can find the matching copy in the build directory
        Returns the matching index or None if no match "other" was found
        """
        matches, missing = self.find_matching_indices([index], scope, can_include_self, can_include_build_generated)
        if len(matches) == 1:
            return list(matches.values())[0]
        return None

    def get(self, key: FUNCTION_INDEX_KEY) -> FunctionIndex:
        raise NotImplementedError

    def find_functions_with_annotation(self, annotation: str) -> Iterator[FUNCTION_INDEX_KEY]:
        raise NotImplementedError("This method should be implemented in the subclass. It is not supported in the base FunctionResolver class.")

    def get_many(self, keys: List[FUNCTION_INDEX_KEY]) -> Dict[FUNCTION_INDEX_KEY, FunctionIndex]:
        return {key: self.get(key) for key in keys}

    def get_with_default(self, key: FUNCTION_INDEX_KEY, default=None) -> Optional[FunctionIndex]:
        try:
            return self.get(key)
        except KeyError:
            return default

    def get_full_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        hk = (key, 'full')
        if hk in self.cached_hashes:
            return self.cached_hashes[hk]

        hash = self.get(key).hash
        self.cached_hashes[hk] = hash
        return hash


    def get_code_line_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        hk = (key, 'code_line')
        if hk in self.cached_hashes:
            return self.cached_hashes[hk]

        meta = self.get(key)
        h = hashlib.md5()
        h.update(meta.code.encode('utf-8'))
        h.update(f"{meta.start_line}".encode('utf-8'))
        hash = h.hexdigest()
        self.cached_hashes[hk] = hash
        return hash

    def get_code_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        hk = (key, 'code')
        if hk in self.cached_hashes:
            return self.cached_hashes[hk]

        meta = self.get(key)
        code = meta.code

        hash = hashlib.md5(code.encode('utf-8')).hexdigest()
        self.cached_hashes[hk] = hash
        return hash

    def get_focus_repo_keys(self, focus_repo_container_path: Optional[Union[Path, str]]) -> List[FUNCTION_INDEX_KEY]:
        if not focus_repo_container_path and self.focus_repo_container_path:
            focus_repo_container_path = self.focus_repo_container_path
        if not focus_repo_container_path:
            raise ValueError("No focus repo container path provided and no default set.")
        return [key for key in self.keys() if key.startswith(str(focus_repo_container_path))]

    def get_filtered_keys(self, key_only_jq_filter_expression: str) -> List[FUNCTION_INDEX_KEY]:
        """
        Get a filtered list of function indices based on a jq filter expression. The jq filter expression operates directly on the function index key.
        """
        if key_only_jq_filter_expression not in self.cached_jq_filter_expression_keys:
            jq_filter = jq.compile(key_only_jq_filter_expression)
            all_keys = self.keys()
            is_valid = jq_filter.input_values(self.keys()).all()
            filtered_keys = [k for k, valid in zip(all_keys, is_valid) if valid]
            self.cached_jq_filter_expression_keys[key_only_jq_filter_expression] = filtered_keys
        return self.cached_jq_filter_expression_keys[key_only_jq_filter_expression]

    def get_filtered(self, key_only_filter_expression: str, full_filter_expression: str) -> List[FUNCTION_INDEX_KEY]:
        """
        Get a filtered list of function indices based on a jq filter expression. Allows you to retrieve keys that are
        filtered based on the key and then filtered again based on the full function index values themselves.

        E.g. `key_only_filter_expression` could be `true` and `full_filter_expression` could be `.focus_repo_relative_path != null` to get all functions that are in the focus repo.
        """
        if (key_only_filter_expression, full_filter_expression) not in self.cached_jq_filter_expression_keys:
            filtered_keys = self.get_filtered_keys(key_only_filter_expression)
            full_jq_filter = jq.compile(full_filter_expression)

            vals_to_filter = [{"key": str(key), "value": prepare_for_json(self.get(key).model_dump())} for key in filtered_keys]
            is_valid = full_jq_filter.input_values(vals_to_filter).all()
            filtered_vals = {k['key']: k['value'] for k, valid in zip(vals_to_filter, is_valid) if valid}

            self.cached_jq_filter_expression_keys[(key_only_filter_expression, full_filter_expression)] = filtered_vals
        return self.cached_jq_filter_expression_keys[(key_only_filter_expression, full_filter_expression)]

    def get_function_code_line(self, key: FUNCTION_INDEX_KEY, line_no: int) -> str:
        if (key, line_no) not in self.cached_code_lines:
            idx = self.get(key)
            try:
                code_line = idx.code.split('\n')[line_no - idx.start_line] if idx is not None else None
            except Exception as e:
                log.warning(f"Error getting function code line for {key}: {e}")
                code_line = None
            self.cached_code_lines[(key, line_no)] = code_line
        return self.cached_code_lines[(key, line_no)]

    def get_function_coverage_for_file(self, path: Union[Path, str], lines: LinesCoverage, function_keys_of_interest=None) -> FunctionCoverageMap:
        if path not in self.cached_lines_to_function:
            start_time = time.time()
            self.cached_lines_to_function[path] = {}
            for key in self.find_by_filename(path):
                start, end = self.get_function_boundary(key)
                self.cached_lines_to_function[path].update({line: key for line in range(start, end + 1)})

            # print(f"Loaded {len(self.cached_lines_to_function[path])} lines to function mappings for {path} in {time.time() - start_time:.2f}s")

        start_time = time.time()
        res = defaultdict(list)
        for line in lines:
            if line.line_number not in self.cached_lines_to_function[path]:
                continue
            containing_function_key = self.cached_lines_to_function[path][line.line_number]
            if function_keys_of_interest is not None and containing_function_key not in function_keys_of_interest:
                continue
            new = CoverageLine(
                line_number=line.line_number,
                count_covered=line.count_covered,
                code=self.get_function_code_line(containing_function_key, line.line_number)
            )
            res[self.cached_lines_to_function[path][line.line_number]].append(new)

        # print(f"Resolved {len(res)} functions for {path} in {time.time() - start_time:.2f}s")
        return res

    def get_function_coverage(self, file_coverage: FileCoverageMap, path_suffixes_of_interest=None, function_keys_of_interest=None) -> FunctionCoverageMap:
        res = {}
        if function_keys_of_interest is not None:
            assert path_suffixes_of_interest is None, "Cannot specify both function keys and path suffixes of interest"
            path_suffixes_of_interest = [os.path.basename(self.get_target_container_path(key)) for key in function_keys_of_interest]
        for path, lines in file_coverage.items():
            if path_suffixes_of_interest is not None and not any(str(path).endswith(suffix) for suffix in path_suffixes_of_interest):
                continue
            res.update(self.get_function_coverage_for_file(path, lines, function_keys_of_interest=function_keys_of_interest))
        return res

    def get_function_coverage_report(self, inputs, function_coverage: FunctionCoverageMap, keys_of_interest: List[FUNCTION_INDEX_KEY]=None):
        reports = []
        if not keys_of_interest:
            keys_of_interest = list(function_coverage.keys())
        for key in keys_of_interest:
            focus_repo_rel_path, target_container_path, func_start_line, func_code = self.get_code(key)

            report = f'# Coverage Report ({len(inputs)} unique inputs)\n'
            report += f'## {key}\n'
            report += f'## {target_container_path}:{func_start_line}\n'
            if key not in function_coverage:
                report += f'No coverage was reached in this function.\n'
                continue

            func_cov_lines = list(sorted(function_coverage[key], key=lambda x: x.line_number))
            report += f'Line | {"Count":8} | Code\n'
            for i, line in enumerate(func_code.split('\n')):
                count = None
                if func_cov_lines and func_cov_lines[0].line_number == i + func_start_line:
                    cur = func_cov_lines.pop(0)
                    count = cur.count_covered

                report += f'{i+func_start_line:4} | {count if count is not None else "":8} | {line}\n'

            reports.append(report)

        report = '\n\n# Function coverage (for the requested functions)\n'
        report += '\n\n'.join(reports if reports else ['ERROR: No coverage was reached in any of the requested functions. You should probably check the coverage of the harness or earlier functions to see where you are getting stuck.'])

        return report



    def resolve_source_location(self, srcloc: SourceLocation, num_top_matches:int=3, allow_build_generated: bool=False, focus_repo_only: bool=False) -> List[Tuple[FUNCTION_INDEX_KEY, List[FunctionIndexRanking]]]:
        contenders_to_rank = []

        if srcloc.function_name:
            # we have a function name. First, if we have a perfect match and there's only one of them, return the perfect match
            perfect_function_matches = []
            imperfect_function_matches = []
            for key in self.find_by_funcname(srcloc.function_name):
                index_entry = self.get(key)
                if index_entry.is_generated_during_build and not allow_build_generated:
                    continue
                if focus_repo_only and self.get(key).focus_repo_relative_path is None:
                    continue
                if index_entry.class_name and srcloc.java_info and srcloc.java_info.class_path: # java info should be high-confidence, this cannot be a match
                    # we have a java function, so we need to check the java info as well
                    if srcloc.java_info.class_path != index_entry.class_name:
                        continue
                ranking = get_function_name_match(srcloc, self.get(key))
                assert ranking, f"Match is None for {srcloc} and {key}"
                if ranking.match_kind == MatchKind.DEFINITELY:
                    perfect_function_matches.append((key, ranking))
                else:
                    imperfect_function_matches.append((key, ranking))

            if perfect_function_matches:
                if len(perfect_function_matches) == 1:
                    return [(
                        perfect_function_matches[0][0],
                        [perfect_function_matches[0][1]]
                    )]

            contenders_to_rank = perfect_function_matches if perfect_function_matches else imperfect_function_matches

        else:
            # we don't have a function name, first, check by filename to find the correct entries
            if artiphishell_should_fail_on_error():
                raise NotImplementedError("This is not implemented yet")
            return None

        return self._rank_contenders(srcloc, contenders_to_rank, num_top_matches)

    def _rank_contenders(
            self,
            srcloc: SourceLocation,
            contenders_to_rank: List[Tuple[FUNCTION_INDEX_KEY, List[FunctionIndexRanking]]],
            num_top_matches: int=3
    ) -> List[Tuple[FUNCTION_INDEX_KEY, List[FunctionIndexRanking]]]:

        if not contenders_to_rank:
            return None

        rankings = []
        for key, ranking in contenders_to_rank:
            # okay, we aggregate the filename, line number, etc. rankings by just summing them up
            total = 0
            rank_vals = []
            # first, we check the relative path
            if relative_path_ranking := get_relative_filename_match(srcloc, self.get(key)):
                total += relative_path_ranking.match_value
                rank_vals.append(('relative_path', relative_path_ranking))
            # then, we check the full file path
            if full_file_path_ranking := get_full_file_path_match(srcloc, self.get(key)):
                total += full_file_path_ranking.match_value
                rank_vals.append(('full_file_path', full_file_path_ranking))
            # then, we check the filename
            if filename_ranking := get_filename_match(srcloc, self.get(key)):
                total += filename_ranking.match_value
                rank_vals.append(('filename', filename_ranking))
            # then, we check the line number
            if line_number_ranking := get_line_number_match(srcloc, self.get(key)):
                total += line_number_ranking.match_value
                rank_vals.append(('line_number', line_number_ranking))
            # then, we check the java info
            if java_info_ranking := get_java_info_match(srcloc, self.get(key)):
                total += java_info_ranking.match_value
                rank_vals.append(('java_info', java_info_ranking))

            rankings.append((key, total, rank_vals))

        # check the sorted rankings
        rankings = sorted(rankings, key=lambda x: x[1], reverse=True) # sort by highest ranking first
        log.debug(f"Rankings for {srcloc}:")
        for i, (key, rank, rank_vals) in enumerate(rankings[:5]):
            log.debug(f"{i+1}. {key}: {rank} with rank values: {rank_vals}")
        log.debug(f"Returning the highest {num_top_matches} rankings: {rankings[:num_top_matches]}")
        return [(r[0], [v[1] for v in r[2]]) for r in rankings[:num_top_matches]] # return the key and the rank values


class LocalFunctionResolver(FunctionResolver):
    def __init__(self, functions_index_path: str, functions_jsons_path: str):
        super().__init__()

        self.functions_index_path = Path(functions_index_path)
        self.functions_jsons_path = Path(functions_jsons_path)

        self.function_full_hashes_write_lock = threading.Lock()
        self.function_full_hashes = None
        self.function_code_line_hashes = None
        self.function_code_hashes = None

        self.cached_func_names = {}

        self.cached_func_codes = {}
        self.cached_focus_repo_relative_paths = {}
        self.cached_target_container_paths = {}
        self.cached_function_boundaries = {}
        self.cached_lines_to_function = {}
        self.cached_by_filename = {}
        self.cached_by_funcname = {}
        self.cached_matching_indices = {}
        self.cached_code_lines = {}
        self.cached_leniency_resolutions = {}
        self.cached_with_annotation = {}

        # This has to be done here to avoid leaking memory from the lru_cache, see https://rednafi.com/python/lru_cache_on_methods/
        self.get = lru_cache(maxsize=2048)(self._get)

        # NOTE: since we want to use the LocalFunctionResolver for a commit index,
        # we need to detect what we are looking at
        try:
            # NOTE: For the base case: I think it's faster to fail here than to try to validate the json with pydantic
            with open(self.functions_index_path, "r") as infile:
                self.functions_index: Dict[str, Path] = {k: Path(v) for k, v in json.load(infile).items()}
        except Exception as e:
            log.warning(f'[INFO] 🔄 Not a full index, trying to load as a commit index.')
            log.warning(f'[INFO] 🔄 Attempting loading a commit index...')
            # However, if we fail, I want to make sure you are passing me a CommitToFunctionIndex
            with open(self.functions_index_path, "r") as infile:
                # FIXME: currently this breaks
                #_ = CommitToFunctionIndex.model_validate(yaml.safe_load(infile.read()))

                # NOTE:
                # If we don't crash, we are looking at a CommitToFunctionIndex! :D
                # The structure of this report is:
                #  { '1_hash' : {'func_sig': 'index'}}
                # Since we are gonna have only 1 commit, let's just extract the internal dict and call
                # it a day.
                try:
                    # FIX: can we have multiple projects' names here?
                    # WARNING: Next two lines are absolutely gorgeous 💋
                    thedata = json.load(infile)
                    thedata = {key: value for commit, commit_funcs_dict in thedata.items() for key, value in commit_funcs_dict.items()}
                    self.functions_index: Dict[str, Path] = {k: Path(v) for k, v in thedata.items()}
                except Exception as e:
                    log.critical(f'[CRITICAL] 🤯 Could not load a function index nor a commit index. Exiting.')
                    log.critical(e)
                    import traceback
                    traceback.print_exc()
                    raise ValueError(f"Could not load a function index nor a commit index. Exiting.")

        for k, v in self.functions_index.items():
            fname = k.split(':')[0]
            # TODO: this is a hack to ignore invalid function names, but we should fix this in the future
            if not any(fname.endswith(suffix) for suffix in VALID_SOURCE_FILE_SUFFIXES):
                log.warning(f"Invalid function name: {fname} in {k!r}")
                continue
            basename = os.path.basename(fname)
            if basename not in self.cached_by_filename:
                self.cached_by_filename[basename] = []
            self.cached_by_filename[basename].append(k)

    def is_ready(self) -> bool:
        return True

    def keys(self) -> List[FUNCTION_INDEX_KEY]:
        return list(self.functions_index.keys())

    def _get(self, key: FUNCTION_INDEX_KEY) -> FunctionIndex:
        if key not in self.functions_index:
            raise KeyError(f"Function {key} not found in index")

        if not (self.functions_jsons_path / self.functions_index[key]).exists():
            raise ValueError(f"Function jsons entry {self.functions_index[key]} does not exist for {key} at {self.functions_jsons_path}: {os.listdir(self.functions_jsons_path)}")

        with open(self.functions_jsons_path / self.functions_index[key], "r") as infile:
            result = FunctionIndex.model_validate(json.load(infile))

        return result

    def __full_scan_of_doom_and_destruction__load_all_hashes_if_needed(self, scope: Literal['all', 'focus', 'non-focus', 'compiled'] = 'all'):
        # Our alg requires that we have EVERY possible function hash loaded so we can search through them

        # TODO we can split this into sub-sets based on the repo scope
        with self.function_full_hashes_write_lock:
            if self.function_full_hashes:
                return


            self.function_full_hashes = defaultdict(list)
            self.function_code_line_hashes = defaultdict(list)
            self.function_code_hashes = defaultdict(list)

            # Load every single goddamn function so that we have the hashes for them

            for key in self.functions_index.keys():
                self.function_full_hashes[
                    self.get_full_hash(key, do_cache=False)
                ].append(key)
                self.function_code_line_hashes[
                    self.get_code_line_hash(key, do_cache=False)
                ].append(key)
                self.function_code_hashes[
                    self.get_code_hash(key, do_cache=False)
                ].append(key)

    def get_funcname(self, key: FUNCTION_INDEX_KEY) -> str:
        if key not in self.cached_func_names:
            self.cached_func_names[key] = self.get(key).funcname
        return self.cached_func_names[key]

    def get_full_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        if self.function_full_hashes and key in self.function_full_hashes:
            return self.function_full_hashes[key]

        return super().get_full_hash(key, do_cache)

    def get_code_line_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        if self.function_code_line_hashes and key in self.function_code_line_hashes:
            return self.function_code_line_hashes[key]

        return super().get_code_line_hash(key, do_cache)

    def get_code_hash(self, key: FUNCTION_INDEX_KEY, do_cache: bool=True) -> str:
        if self.function_code_hashes and key in self.function_code_hashes:
            return self.function_code_hashes[key]

        return super().get_code_hash(key, do_cache)

    def get_focus_repo_relative_path(self, key: FUNCTION_INDEX_KEY) -> Optional[Path]:
        if key not in self.cached_focus_repo_relative_paths:
            res = self.get(key)
            self.cached_focus_repo_relative_paths[key] = res.focus_repo_relative_path
        return self.cached_focus_repo_relative_paths[key]

    def get_target_container_path(self, key: FUNCTION_INDEX_KEY) -> Path:
        if key not in self.cached_target_container_paths:
            res = self.get(key)
            self.cached_target_container_paths[key] = res.target_container_path
        return self.cached_target_container_paths[key]

    def get_code(self, key: FUNCTION_INDEX_KEY) -> Tuple[Path, Path, int, str]:
        if key not in self.cached_func_codes:
            idx = self.get(key)
            self.cached_func_codes[key] = (idx.focus_repo_relative_path, idx.target_container_path, idx.start_line, idx.code)
        return self.cached_func_codes[key]

    def get_function_boundary(self, key: FUNCTION_INDEX_KEY) -> Tuple[int, int]:
        if key not in self.cached_function_boundaries:
            idx = self.get(key)
            self.cached_function_boundaries[key] = (idx.start_line, idx.end_line)
        return self.cached_function_boundaries[key]

    def find_by_funcname(self, s: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if s not in self.cached_by_funcname:
            self.cached_by_funcname[s] = [key for key in self._find_matching_indices(s) if self.get_funcname(key).split('::')[-1] == s]
        for key in self.cached_by_funcname[s]:
            yield key

    def find_functions_with_annotation(self, annotation: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if annotation not in self.cached_with_annotation.keys():
            self.cached_with_annotation[annotation] = []
            for key in self.functions_index.keys():
                func = self.get(key)
                if func.language_specific_info and "annotations" in func.language_specific_info.keys():
                    for found_annotation in func.language_specific_info["annotations"]:
                        if found_annotation['identifier'] == annotation:
                            self.cached_with_annotation[annotation].append(key)
        for key in self.cached_with_annotation[annotation]:
            yield key

    def find_matching_indices(
        self,
        indices: List[FUNCTION_INDEX_KEY],
        scope: Literal['all', 'focus', 'non-focus', 'compiled'] = 'focus',
        can_include_self: bool=True,
        can_include_build_generated: bool = True,
    ) -> Tuple[
        Dict[FUNCTION_INDEX_KEY, FUNCTION_INDEX_KEY],
        List[FUNCTION_INDEX_KEY]
    ]:
        assert scope in ['all', 'focus', 'non-focus', 'compiled'], f"Invalid scope: {scope}"
        if scope == 'all':
            assert not can_include_self, "can_include_self=true on `all` scope will always return self..."

        cache = self.cached_matching_indices
        out_map = {}

        if len(indices) == 0:
            return out_map, []

        if len(indices) == 1:
            # Rather than doing the more complex Aho-Corasick search, we can just do a simple lookup by funcname
            found = self.get(indices[0])
            if not found:
                return out_map, indices

            # Loads the cache with all the matches for this funcname
            self.find_by_funcname(found.funcname)

        missing = set()

        for goal_k in indices:
            cache_key = (goal_k, scope, can_include_self)
            # Check if we have found this match before
            if goal_k in cache:
                cached_v = cache[goal_k]
                if cached_v is None:
                    missing.add(goal_k)
                else:
                    out_map[goal_k] = cached_v
                continue

        to_find = [
            k for k in indices
            if not (k in out_map) and not (k in missing)
        ]

        if not to_find:
            return out_map, list(missing)

        log.warning(f"Before full scan {time.perf_counter()}")

        self.__full_scan_of_doom_and_destruction__load_all_hashes_if_needed(scope)

        log.warning(f"After full scan {time.perf_counter()}")

        for goal_key in to_find:
            matches = set()

            full_hash = self.get_full_hash(goal_key)
            matches |= set(self.function_full_hashes.get(full_hash, []))

            code_line_hash = self.get_code_line_hash(goal_key)
            matches |= set(self.function_code_line_hashes.get(code_line_hash, []))

            code_hash = self.get_code_hash(goal_key)
            matches |= set(self.function_code_hashes.get(code_hash, []))

            meta = self.get(goal_key)

            #log.warning(f"--- Looking for {goal_key} matches (focus repo relative path: {meta.focus_repo_relative_path})")
            def allow_build_generated(key: FUNCTION_INDEX_KEY) -> bool:
                if can_include_build_generated:
                    return True
                return not self.get(key).is_generated_during_build

            #log.warning(f"Matches: {matches}")
            def is_in_scope(key: FUNCTION_INDEX_KEY) -> bool:
                if scope == 'focus':
                    return self.get_focus_repo_relative_path(key) is not None
                elif scope == 'non-focus':
                    return self.get_focus_repo_relative_path(key) is None
                elif scope == 'compiled':
                    return self.get(key).was_directly_compiled
                else:
                    return True

            # filter down the matches based on the scope
            log.warning(f"Matches before scope filter: {matches}")
            matches = {key for key in matches if is_in_scope(key) and allow_build_generated(key)}
            log.warning(f"Matches after scope filter: {matches}")


            should_have_self = can_include_self and is_in_scope(goal_key)
            #log.warning(f"Should have self: {should_have_self}")

            if should_have_self:
                matches.add(goal_key)
            else:
                matches.discard(goal_key)

            if not matches:
                missing.add(goal_key)
                continue

            if len(matches) == 1:
                best_match_key = list(matches)[0]
            else:
                # If we have multiple matches, we need to rank them
                srcloc = function_index_to_source_location(goal_key, meta)

                contenders = [(key, None) for key in matches]

                ranking = self._rank_contenders(srcloc, contenders, num_top_matches=1)
                best_match_key = ranking[0][0]

            assert best_match_key is not None, f"Could not find a best match for {goal_key}"

            out_map[goal_key] = best_match_key
            cache_key = (goal_key, scope, can_include_self)
            cache[cache_key] = best_match_key

        if missing:
            log.warning(f"Could not find matches for {len(missing)} indices")
            #log.warning(f"Remaining: {missing}")
            for k in missing:
                cache_key = (k, scope, can_include_self)
                cache[cache_key] = None

        return out_map, list(missing)


    def find_by_filename(self, s: Union[Path, str]) -> Iterator[FUNCTION_INDEX_KEY]:
        basename = os.path.basename(s)
        if basename not in self.cached_by_filename:
            self.cached_by_filename[basename] = list(self._find_matching_indices(basename))

        for key in self.cached_by_filename[basename]:
            rel_path = self.get_target_container_path(key).relative_to('/')
            if str(rel_path).endswith(str(s)) or str(s).endswith(str(rel_path)):
                yield key

    def _find_matching_indices(self, s: str) -> Iterator[FUNCTION_INDEX_KEY]:
        for key in self.functions_index.keys():
            if s in key:
                yield key
        return None

    def resolve_with_leniency(self, name: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if not name:
            return

        if name in self.functions_index:
            yield name
            return

        if re.fullmatch(r".*:\d+", name):
            # okay, we have a filename with a line number, let's just return it
            filename, line_number = name.rsplit(':', 1)
            line_number = int(line_number)
            for key in self.find_by_filename(filename):
                start, end = self.get_function_boundary(key)
                if start <= line_number <= end:
                    yield key
                    return
            raise ValueError(f"Could not find any function matching {name}.")

        if name in self.cached_leniency_resolutions:
            yield from self.cached_leniency_resolutions[name]
            return

        func = list(self.find_by_funcname(name))
        if len(func) >= 1:
            yield from func
            return

        func = list(self._find_matching_indices(name))
        if len(func) >= 1:
            yield from func
            return

        if '(' in name:
            # okay, try for java to split the path
            # import ipdb; ipdb.set_trace()
            no_signature = name.rsplit('(', 1)[0]
            yield from self.resolve_with_leniency(no_signature)
            return

        if '.' in name:
            # okay, try for java to split the path
            # import ipdb; ipdb.set_trace()
            class_name, name = name.rsplit('.', 1)
            class_name = class_name.replace('.', '/') + '.java'
            func_keys = list(self.find_by_filename(class_name))
            func_keys = [k for k in func_keys if self.get_funcname(k) == name]
            if len(func_keys) > 0:
                yield from func_keys
                return

            func_keys = list(self.find_by_funcname(name))
            if len(func_keys) > 0:
                yield from func_keys
                return
        if match := re.fullmatch(r"source:(.+):(\d+):(\d+)::", name):
            # it looks like this is supposed to be a function index key.
            path_match = match.group(1)
            line_match = match.group(2)
            possible_keys = list(self.find_by_filename(path_match))
            line_match = int(line_match)
            filtered = [k for k in possible_keys if self.get_function_boundary(k)[0] <= line_match <= self.get_function_boundary(k)[1]]
            if len(filtered) > 0:
                yield from filtered
                return
            # otherwise, it's clearly trying to hallucinate a key. Tell it go kick rocks.
            raise ValueError(f"This looks like a function index key but we could not find any function matching {name}. This function key does not exist, please move on.")

        if '::' in name:
            # okay, try for cpp try to split the path
            # import ipdb; ipdb.set_trace()
            class_name, name = name.rsplit('::', 1)
            possible_keys = list(self._find_matching_indices(class_name))
            # import ipdb; ipdb.set_trace()
            filtered = [k for k in possible_keys if self.get_funcname(k) == name and all(sub in k for sub in class_name.split('::'))]
            if len(filtered) > 0:
                yield from filtered
                return
        if name.upper().startswith('OSS_FUZZ_'):
            # okay, try for cpp to split the path
            # import ipdb; ipdb.set_trace()
            name = name[len('OSS_FUZZ_'):]
            func_keys = list(self.find_by_funcname(name))
            if len(func_keys) > 0:
                yield from func_keys
                return

        raise ValueError(f"Could not find any function matching {name}.")

class RemoteFunctionResolver(FunctionResolver):
    def __init__(self, cp_name: str, project_id: Union[str, PDT_ID]):
        super().__init__()

        self.url = os.getenv('FUNC_RESOLVER_URL', None)
        if os.getenv('CRS_TASK_NUM'):
            self.url = self.url.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
        else:
            if 'TASKNUM' in self.url:
                raise ValueError("Env CRS_TASK_NUM is not set but FUNC_RESOLVER_URL contains TASKNUM")


        if self.url is None:
            raise ValueError("FUNC_RESOLVER_URL is not set")
        self.cp_name = cp_name
        self.project_id = project_id

        self.cached_func_names = {}
        self.cached_func_codes = {}
        self.cached_focus_repo_relative_paths = {}
        self.cached_target_container_paths = {}
        self.cached_function_boundaries = {}
        self.cached_lines_to_function = {}
        self.cached_by_filename = {}
        self.cached_by_funcname = {}
        self.cached_code_lines = {}
        self.cached_matching_indices = {}
        self.cached_leniency_resolutions = {}
        self.cached_with_annotation = {}

        self.get = lru_cache(maxsize=512)(self._get)
    
    def is_ready(self) -> bool:
        r = requests.get(f"{self.url}/health", params={
            "cp_name": self.cp_name,
            "project_id": self.project_id,
        })

        if r.status_code != 200:
            return False
        
        result = r.json()
        if result.get("status", None) == "error" and result.get('data', None) == 'Server not initialized':
            return False
        
        return True

    def _make_request(self, endpoint: str, data: dict) -> dict:
        while True:
            r = requests.post(f"{self.url}/{endpoint}", data=data)
            if r.status_code != 200:
                # These are always critical errors we must fix
                assert False, f"Internal Server Error in /{endpoint} : {r.text}"
            result = r.json()
            if result.get("status", None) == "error" and result.get('data', None) == 'Server not initialized':
                log.warning(f"Function resolver server not initialized, waiting 30 seconds before retrying /{endpoint}")
                time.sleep(30)
                continue
            return result

    def keys(self):
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id
        }
        result = self._make_request("keys", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None: {result}"
        if api_status == "error":
            # This means the function was not found in the index.
            # Users will have to handle this Exception themselves
            raise KeyError(f"Function keys not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error: {result}"
            # This means the function was found in the index.
            # The response should be a dict with the function index
            return result.get("data", [])

    def _get(self, key: FUNCTION_INDEX_KEY) -> FunctionIndex:
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "key": key
        }

        result = self._make_request("get", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {key}: {result}"
        if api_status == "error":
            # This means the function was not found in the index.
            # Users will have to handle this Exception themselves
            raise KeyError(f"Function {key} not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"
            # This means the function was found in the index.
            # The response should be a dict with the function index
            return FunctionIndex.model_validate(result.get("data", None))

    def get_many(self, keys):
        # optimized implementation for getting many keys in one request
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "keys": keys
        }

        result = self._make_request("get_many", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {keys}: {r.text}"
        if api_status == "error":
            # This means the function was not found in the index.
            # Users will have to handle this Exception themselves
            raise KeyError(f"Function {keys} not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {keys}: {result}"
            # This means the function was found in the index.
            # The response should be a dict with the function index
            return {key: FunctionIndex.model_validate(value) for key, value in result.get("data", {}).items()}

    def get_focus_repo_keys(self, focus_repo_container_path):
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "focus_repo_container_path": focus_repo_container_path
        }

        result = self._make_request("get_focus_repo_keys", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {focus_repo_container_path}: {result}"
        if api_status == "error":
            raise KeyError(f"Function keys not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {focus_repo_container_path}: {result}"
            # This means the function was found in the index.
            return result.get("data", [])

    def get_filtered_keys(self, key_only_jq_filter_expression: str) -> List[FUNCTION_INDEX_KEY]:
        """
        Get a filtered list of function indices based on a jq filter expression. The jq filter expression operates directly on the function index key.
        """
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "key_only_filter_expression": key_only_jq_filter_expression
        }

        result = self._make_request("get_filtered_keys", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {key_only_jq_filter_expression}: {result}"
        if api_status == "error":
            raise KeyError(f"Function keys not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {key_only_jq_filter_expression}: {result}"
            # This means the function was found in the index.
            return result.get("data", [])

    def get_filtered(self, key_only_filter_expression: str, full_filter_expression: str) -> Dict[FUNCTION_INDEX_KEY, FunctionIndex]:
        """
        Get a filtered list of function indices based on a jq filter expression. The jq filter expression operates directly on the function index key.
        """
        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "key_only_filter_expression": key_only_filter_expression,
            "full_filter_expression": full_filter_expression
        }
        result = self._make_request("get_filtered", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {key_only_filter_expression}: {result}"
        if api_status == "error":
            raise KeyError(f"Function keys not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {key_only_filter_expression}: {result}"
            # This means the function was found in the index.
            return {k: FunctionIndex.model_validate(v) for k, v in result.get("data", {}).items()}

    def get_funcname(self, key: FUNCTION_INDEX_KEY) -> str:
        if key in self.cached_func_names:
            return self.cached_func_names[key]
        else:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "key": key
            }

            result = self._make_request("get_funcname", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {key}: {result}"

            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"Function name for {key} not found in index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"
                # This means the function was found in the index.
                func_name = result.get("data", None)
                assert(func_name is not None), f"Function name is None for {key}: {result}"

                self.cached_func_names[key] = func_name
                return self.cached_func_names[key]

    def get_focus_repo_relative_path(self, key: FUNCTION_INDEX_KEY) -> Optional[Path]:
        if key in self.cached_focus_repo_relative_paths:
            return self.cached_focus_repo_relative_paths[key]
        else:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "key": key
            }
            result = self._make_request("get_focus_repo_relative_path", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {key}: {result}"
            if api_status == "error":
                raise KeyError(f"Relative path for {key} not found in index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"
                # This means the function was found in the index.
                rel_path = result.get("data", None)
                assert(rel_path is not None), f"rel_path is None for {key}: {result}"

                # Convert to a tuple RelativePathKind and Path objects
                self.cached_focus_repo_relative_paths[key] = (RelativePathKind(rel_path[0]), Path(rel_path[1]))

                return self.cached_focus_repo_relative_paths[key]

    def get_target_container_path(self, key: FUNCTION_INDEX_KEY) -> Path:
        if key in self.cached_target_container_paths:
            return self.cached_target_container_paths[key]

        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "key": key
        }
        result = self._make_request("get_target_container_path", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {key}: {result}"
        if api_status == "error":
            raise KeyError(f"Target container path for {key} not found in index: {result}")
        else:
            assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"

            target_container_path = result.get("data", None)
            assert(target_container_path is not None), f"Target container path is None for {key}: {r.text} {result}"

            self.cached_target_container_paths[key] = Path(target_container_path)
            return self.cached_target_container_paths[key]

    def get_code(self, key: FUNCTION_INDEX_KEY) -> Tuple[Path, Path, int, str]:
        if key in self.cached_func_codes:
            return self.cached_func_codes[key]
        else:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "key": key
            }

            result = self._make_request("get_code", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {key}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"Code for {key} not found in index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"
                # This means the function was found in the index.
                # The response should be a list of 4 elements: RelativePathKind, Path, start_line, code
                code = result.get("data", None)
                assert(code is not None), f"Code is None for {key}: {result}"
                assert(len(code) == 4), f"Code is not a list of 4 elements for {key}: {result}"
                # Convert to a tuple RelativePathKind and Path objects
                self.cached_func_codes[key] = (Path(code[0]) if code[0] else None, Path(code[1]) if code[1] else None, code[2], code[3])
                return self.cached_func_codes[key]

    def get_function_boundary(self, key: FUNCTION_INDEX_KEY) -> Tuple[int, int]:
        if key in self.cached_function_boundaries:
            return self.cached_function_boundaries[key]
        else:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "key": key
            }

            result = self._make_request("get_function_boundary", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {key}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"Function boundary for {key} not found in index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {key}: {result}"
                # This means the function was found in the index.
                func_boundaries = result.get("data", None)
                self.cached_function_boundaries[key] = (func_boundaries[0], func_boundaries[1])
                return self.cached_function_boundaries[key]

    def find_functions_with_annotation(self, annotation: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if not annotation:
            return

        if annotation not in self.cached_with_annotation:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "annotation": annotation
            }
            result = self._make_request("find_functions_with_annotation", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {annotation}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"No results for name {annotation} in function index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {annotation}: {result}"
                # This means the function was found in the index.
                # The response should be a list of function keys
                matches = result.get("data", None)
                assert(matches is not None), f"matches is None for {annotation}: {result}"

                self.cached_with_annotation[annotation] = matches
        yield from self.cached_with_annotation[annotation]

    def find_by_funcname(self, s: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if not s:
            return

        if s not in self.cached_by_funcname:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "s": s
            }

            result = self._make_request("find_by_funcname", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {s}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"No results for name {s} in function index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {s}: {result}"
                # This means the function was found in the index.
                # The response should be a list of function keys
                matches = result.get("data", None)
                assert(matches is not None), f"matches is None for {s}: {result}"

                self.cached_by_funcname[s] = matches

        yield from self.cached_by_funcname[s]

    def find_matching_indices(
        self,
        indices: List[FUNCTION_INDEX_KEY],
        scope: Literal['all', 'focus', 'non-focus', 'compiled'] = 'focus',
        can_include_self: bool=True,
        can_include_build_generated: bool = True,
    ) -> Tuple[
        Dict[FUNCTION_INDEX_KEY, FUNCTION_INDEX_KEY],
        List[FUNCTION_INDEX_KEY]
    ]:
        if scope == 'all':
            assert not can_include_self, "can_include_self=true on `all` scope will always return self..."

        cached_values = {}
        cached_missing = []
        uncached_indices = []
        for k in indices:
            cache_key = (k, scope, can_include_self)
            if cache_key in self.cached_matching_indices:
                cached_val = self.cached_matching_indices[cache_key]
                if cached_val is not None:
                    cached_values[k] = cached_val
                else:
                    cached_missing.append(k)
            else:
                uncached_indices.append(k)

        if len(uncached_indices) == 0:
            return cached_values, cached_missing

        data = {
            "cp_name": self.cp_name,
            "project_id": self.project_id,
            "indices": indices,
            "scope": scope,
            "can_include_self": can_include_self
        }

        result = self._make_request("find_matching_indices", data)

        api_status = result.get("status", None)
        assert(api_status is not None), f"API status code is None for {len(indices)} strings: {result}"
        if api_status == "error":
            raise Exception(f"Error in find_matching_indices for {len(indices)} strings: {result}")

        assert(api_status == "success"), f"API status code is not success|error for {len(indices)} strings: {result}"

        # The response should be a list of function keys
        matches = result.get("matching", None)
        for k,v in matches.items():
            self.cached_matching_indices[k] = v

        missing = result.get("missing", None)
        for k in missing:
            self.cached_matching_indices[k] = None

        # combine the previous cached values with the new ones
        cached_values.update(matches)
        cached_missing.extend(missing)

        return cached_values, cached_missing



    def find_by_filename(self, s: Union[Path, str]) -> Iterator[FUNCTION_INDEX_KEY]:
        if not s:
            return

        if s not in self.cached_by_filename:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "s": str(s)
            }
            result = self._make_request("find_by_filename", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {s}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"No results for filename {s} in function index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {s}: {result}"
                # This means the function was found in the index.
                # The response should be a list of function keys
                matches = result.get("data", None)
                assert(matches is not None), f"matches is None for {s}: {result}"

                self.cached_by_filename[s] = matches

        yield from self.cached_by_filename[s]

    def resolve_with_leniency(self, name: str) -> Iterator[FUNCTION_INDEX_KEY]:
        if not name:
            return

        if name not in self.cached_leniency_resolutions:
            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
                "name": name
            }

            result = self._make_request("resolve_with_leniency", data)

            api_status = result.get("status", None)
            assert(api_status is not None), f"API status code is None for {name}: {result}"
            if api_status == "error":
                # This means the function was not found in the index.
                # Users will have to handle this Exception themselves
                raise KeyError(f"No results for name {name} in function index: {result}")
            else:
                assert(api_status == "success"), f"API status code is not success|error for {name}: {result}"
                # This means the function was found in the index.
                # The response should be a list of function keys
                matches = result.get("data", None)
                assert(matches is not None), f"matches is None for {name}: {result}"
                self.cached_leniency_resolutions[name] = matches

        yield from self.cached_leniency_resolutions[name]

    def upload(self, full_functions_index_path: Path, full_functions_index_jsons_dir: Path):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            (temp_dir / 'functions_index').mkdir()
            (temp_dir / 'functions_jsons').mkdir()
            shutil.copy(full_functions_index_path, temp_dir / self.project_id)
            subprocess.run(
                ["tar", "-cvf", "functions_index/functions_index.tar", self.project_id],
                check=True,
                cwd=temp_dir,
            )
            os.unlink(temp_dir / self.project_id)

            shutil.copytree(full_functions_index_jsons_dir, temp_dir / self.project_id)
            subprocess.run(
                ["tar", "-cvf", os.path.join(temp_dir, "functions_jsons/functions_jsons.tar"), '.'],
                check=True,
                cwd=temp_dir / self.project_id,
            )
            shutil.rmtree(temp_dir / self.project_id)

            subprocess.run(
                ["tar", "-cvf", "data.tar", "functions_index/functions_index.tar", "functions_jsons/functions_jsons.tar"],
                check=True,
                cwd=temp_dir,
            )

            data = {
                "cp_name": self.cp_name,
                "project_id": self.project_id,
            }
            with open(temp_dir / "data.tar", "rb") as f:
                response = requests.post(
                    f"{self.url}/init_server",
                    data=data,
                    files={"data": f}
                )
                response.raise_for_status()
                return response.json()



def function_resolver_upload():
    import argparse
    parser = argparse.ArgumentParser(description='Upload function index to the function resolver server')
    parser.add_argument('project_name', type=str, help='Name of the project (aka cp_name)')
    parser.add_argument('project_id', type=str, help='Project ID')
    parser.add_argument('full_functions_index_path', type=Path, help='Path to the full functions index')
    parser.add_argument('full_functions_index_jsons_dir', type=Path, help='Path to the full functions index jsons dir')
    args = parser.parse_args()

    resolver = RemoteFunctionResolver(args.project_name, args.project_id)
    result = resolver.upload(args.full_functions_index_path, args.full_functions_index_jsons_dir)
    print(result)

def function_resolver_upload_backup():
    import argparse
    parser = argparse.ArgumentParser(description='Upload function index to the function resolver server')
    parser.add_argument('backup_dir', type=Path, help='Path to the backup directory')
    args = parser.parse_args()

    project_ids = []
    for f in os.listdir( args.backup_dir / 'generate_full_function_index.target_functions_index'):
        assert f.split('.')[0] == f, f"the type of target_functions_index has changed: {f}"
        project_ids.append(f.split('.')[0])

    for project_id in project_ids:
        with tempfile.TemporaryDirectory() as tempdir:
            if not os.path.isdir(args.backup_dir / 'generate_full_function_index.target_functions_jsons_dir' / project_id):
                tar_path = args.backup_dir / 'generate_full_function_index.target_functions_jsons_dir' / f'{project_id}.tar.gz'
                # extract the tar
                subprocess.check_call(
                    ["tar", "-xvf", tar_path],
                    cwd=tempdir,
                )
            else:
                subprocess.check_call(
                    ['rsync', '-ra', str(args.backup_dir / 'generate_full_function_index.target_functions_jsons_dir' / project_id) + '/', tempdir],
                )

            full_functions_index_jsons_dir = Path(tempdir)
            full_functions_index_path = args.backup_dir / 'generate_full_function_index.target_functions_index' / project_id
            crs_task = args.backup_dir / 'generate_full_function_index.crs_task' / f'{project_id}.yaml'
            with open(crs_task, 'r') as f:
                project_name = yaml.safe_load(f)['project_name']
            resolver = RemoteFunctionResolver(project_name, project_id)
            result = resolver.upload(full_functions_index_path, full_functions_index_jsons_dir)
            print(result)
