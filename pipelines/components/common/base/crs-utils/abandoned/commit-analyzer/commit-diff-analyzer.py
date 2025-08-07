#!/usr/bin/env python3
from pathlib import Path
import os
import difflib
import re
import argparse
import shutil
import subprocess
import json
import tempfile

import git
import yaml
"""
    This is a script that takes:
        a). the path to target git repository
        b). the path to source git repository
        c). target git commit id
        d). closest commit id of source git repo
    Output:
        functions that are different in these two commits
        It should have the following dictionary format:
        {
            "file_name" : {
                "functions":
                    [("source function content", "target function content"), ...]
                "diff": "diff content"
            }
        }
"""


def diff(target_repo_path: Path, source_repo_path: Path, file_extension: str):
    target_files = get_files_with_extension(target_repo_path, file_extension)
    source_files = get_files_with_extension(source_repo_path, file_extension)
    diff_dict = {}
    '''
    common_files = set(targe_files).intersection(set(source_files))
    source_unique_files = set(source_files) - set(targe_files)
    target_unique_files = set(targe_files) - set(source_files)
    print(common_files)
    '''
    all_files = set(target_files).union(set(source_files))
    for file in all_files:
        f1 = os.path.join(source_repo_path, file)
        f2 = os.path.join(target_repo_path, file)
        if not os.path.exists(f1):
            lines1 = []
            #f1 = '/dev/null'
            with open(f2) as __f:
                lines2 = __f.readlines()
        elif not os.path.exists(f2):
            lines2 = []
            #f2 = '/dev/null'
            # lines1 = open(f1).readlines()
            with open(f1) as __f:
                lines1 = __f.readlines()
        else:
            # lines1 = open(f1).readlines()
            # lines2 = open(f2).readlines()
            with open(f1) as __f:
                lines1 = __f.readlines()
            with open(f2) as __f:
                lines2 = __f.readlines()
        
        if lines1 == lines2:
            continue

        diff = difflib.unified_diff(
            lines1,
            lines2,
            fromfile="a/"+file,
            tofile="b/"+file,
            lineterm='\n'
            )
        diff_dict[file] = {
            'diff': ''.join(diff)
        }
    final_diff = {}
    for key, value in diff_dict.items():
        if diff_dict[key]['diff'] != '':
            final_diff[key] = {'diff': value['diff']}
    #print(final_diff.keys())
    #print(final_diff["core/src/main/java/hudson/PluginWrapper.java"]['diff'])
    print(f"Files with changes: {final_diff.keys()}")
    return final_diff

def get_files_with_extension(target_repo_path: Path, file_extension: str):
    files = [
        os.path.relpath(file, target_repo_path) for file in target_repo_path.rglob(f'*.{file_extension}') if file.is_file() and '.git' not in file.parts and 'resources' not in file.parts
    ]
    return files


def extract_functions(target_dir: Path, source_dir: Path, file_extension: str):
    """
    :param target_repo: the path to target git repository
    :param source_repo: the path to source git repository
    :return: functions that are different in these two commits    print(target_repo_path)
    print(source_repo_path)
    """
    diff_dict = diff(target_dir, source_dir, file_extension)
    for file, value in diff_dict.items():
        chunks = extract_chunk_info(diff_dict[file]['diff'])
        function_starts = []
        function_ends = []
        function_starts_source = []
        function_ends_source = []
        if os.path.exists(os.path.join(target_dir, file)):
            function_starts = get_function_line_nums(os.path.join(target_dir, file))
            function_ends = get_end_line_numbers(os.path.join(target_dir, file), function_starts)
        if os.path.exists(os.path.join(source_dir, file)):
            function_starts_source = get_function_line_nums(os.path.join(source_dir, file))
            function_ends_source = get_end_line_numbers(os.path.join(source_dir, file), function_starts_source)
        diff_dict[file]['functions'] = []
        for chunk in chunks:
            f_old = ""
            f_new = ""
            chunk_old = (chunk['start_line_old'], chunk['lines_old'])
            chunk_new = (chunk['start_line_new'], chunk['lines_new'])
            if chunk_old[1] != 0 or chunk_old[1] != 0:
                f_old = extract_function(os.path.join(source_dir, file), chunk_old, function_starts_source, function_ends_source)
            if chunk_new[1] != 0 or chunk_new[1] != 0:
                f_new = extract_function(os.path.join(target_dir, file), chunk_new, function_starts, function_ends)
            #function_name = f_old.split('\n')[0].strip().rstrip('{}')
            diff_dict[file]['functions'].append((f_old, f_new))
    return diff_dict
    '''
    print(f)
    print(diff_dict['core/src/main/java/hudson/PluginWrapper.java']['diff'])
    chunks = extract_chunk_info(diff_dict["core/src/main/java/hudson/PluginWrapper.java"]['diff'])
    print(chunks)
    function_starts = get_function_line_nums(os.path.join(target_repo, "core/src/main/java/hudson/PluginWrapper.java"))
    function_ends = get_end_line_numbers(os.path.join(target_repo, "core/src/main/java/hudson/PluginWrapper.java"), function_starts)
    chunk_old = (chunks[0]['start_line_old'], chunks[0]['lines_old'])
    chunk_new = (chunks[1]['start_line_new'], chunks[1]['lines_new'])
    f = extract_function(os.path.join(target_repo, "core/src/main/java/hudson/PluginWrapper.java"), chunk_new, function_starts, function_ends)
    print(f)
    '''

def extract_chunk_info(diff_output):
    chunks = []
    lines = diff_output.split('\n')
    
    for i, line in enumerate(lines):
        if line.startswith('@@'):
            chunk_info = line.split('@@')[1].strip()
            #print(chunk_info)
            old, new = chunk_info.split(' ')
            
            start_line_old = int(old.split(',')[0][1:])
            lines_old = int(old.split(',')[1]) if ',' in old else 1
            
            start_line_new = int(new.split(',')[0][1:])
            lines_new = int(new.split(',')[1]) if ',' in new else 1
            
            chunk = {
                'start_line_old': start_line_old,
                'lines_old': lines_old,
                'start_line_new': start_line_new,
                'lines_new': lines_new,
                'content': []
            }
            
            j = i + 1
            while j < len(lines) and not lines[j].startswith('@@'):
                chunk['content'].append(lines[j])
                j += 1
            
            chunks.append(chunk)
    
    return chunks

def get_function_line_nums(filename):
    output = subprocess.check_output(['ctags', '-x', '--c-kinds=f', filename])
    lines = output.splitlines()
    line_nums = []
    for line in lines:
        line = line.decode('utf-8').split()
        char = list(filter(None, line))
        if 'method' not in char or '{' not in char:
            continue
        ind = char.index('method') + 1
        line_num = find_first_int(char[ind:])
        line_nums.append(int(line_num))
    return line_nums

def find_first_int(lst):
    for i in lst:
        try:
            int(i)
            return i
        except ValueError:
            pass
    return None
    
def get_end_line_numbers(filename, start_lines):
    end_lines = []
    with open(filename, "r") as f:
        lines = f.readlines()

    for start_line in start_lines:
        brace_count = 0
        counted = False
        for i, line in enumerate(lines[start_line-1:], start = start_line):
            brace_count += line.count('{')
            if brace_count > 0:
                counted = True
            brace_count -= line.count('}')
            if brace_count == 0 and counted == True:
                end_lines.append(i)
                break
    return end_lines   

def extract_function(filename, chunk, start_lines, end_lines):
    # chunk is a tuple of start_line and line_num
    assert len(start_lines) == len(end_lines)
    code = ""
    for i in range(len(start_lines)):
        function_start_line = start_lines[i]
        function_end_line = end_lines[i]
        chunk_start, line_num = chunk
        chunk_end = chunk_start + line_num - 1
        #print(function_start_line, function_end_line, chunk_start, chunk_end, function_start_line, function_end_line)
        # if (chunk_start >= function_start_line and chunk_end <= function_end_line) \
        #     or (chunk_start <= function_start_line and function_end_line <= chunk_end) \
        #     or (chunk_start <= function_end_line and chunk_end >= function_end_line):

        if min(chunk_end, function_end_line) - max(chunk_start, function_start_line) > 0:
            code_append, i = process_file(filename, function_start_line)
            code += code_append
    return code

#TODO: The decorators or annotators like @Override, @Deprecated, @SuppressWarnings("deprecation") are not included in the returned code       
def process_file(filename, line_num):
    print("opening " + filename + " on line " + str(line_num))

    code = ""
    cnt_braket = 0
    found_start = False
    found_end = False

    with open(filename, "r") as f:
        for i, line in enumerate(f):
            if(i >= (line_num - 1)):
                code += line

                if (not line.startswith("//")) and line.count("{") > 0:
                    found_start = True
                    cnt_braket += line.count("{")

                if (not line.startswith("//")) and line.count("}") > 0:
                    cnt_braket -= line.count("}")

                if cnt_braket == 0 and found_start == True:
                    found_end = True
                    return code, i+1
                
def extract_changed_functions_git_repo(git_repo_dir, file_extension: str):
    repo_handler = git.Repo(git_repo_dir)
    with tempfile.TemporaryDirectory() as primary_copy, tempfile.TemporaryDirectory() as secondary_copy:
        primary_copy = Path(primary_copy)
        secondary_copy = Path(secondary_copy)
        print(f'Copying {git_repo_dir} to {primary_copy}...')
        shutil.copytree(git_repo_dir, primary_copy, dirs_exist_ok=True)
        print(f'Copying {git_repo_dir} to {primary_copy}...')
        shutil.copytree(git_repo_dir, secondary_copy, dirs_exist_ok=True)
        assert (primary_copy / '.git').is_dir()
        assert (secondary_copy / '.git').is_dir()

        repo_primary = git.Repo(primary_copy)
        repo_secondary = git.Repo(secondary_copy)
        result = {}
        for commit in repo_handler.iter_commits():
            print(f'Processing commit {commit.hexsha}...')
            if not commit.parents:
                continue
            parent = commit.parents[0]
            repo_primary.git.checkout(commit.hexsha)
            repo_secondary.git.checkout(parent.hexsha)

            result[commit.hexsha] = extract_functions(primary_copy, secondary_copy, file_extension)
    return result
            
def extract_changed_functions_challenge_project(cp_path: Path, file_extension: str):
    project_yaml = Path(cp_path) / "project.yaml"
    assert project_yaml.is_file()
    with open(project_yaml, "r") as f:
        project = yaml.safe_load(f)

    result = {}

    for key, value in project['cp_sources'].items():
        repo_dir = cp_path / 'src' / key
        if 'directory' in value:
            repo_dir = cp_path / value['directory']

        assert repo_dir.exists()
        rel_dir = os.path.relpath(repo_dir, cp_path)
        result[str(rel_dir)] = extract_changed_functions_git_repo(repo_dir, file_extension)
        
    return result

# The generated functions are without comments
def main():
    parser = argparse.ArgumentParser(description='Extract functions that are changed by each commit for all sources in a given challenge_project')
    parser.add_argument('challenge_project', type=str, help='the path to the challenge project') # Target should be the competition repo
    parser.add_argument('file_extension', type=str, help='file extension to be considered, currently supports java and c')
    args = parser.parse_args()
    
    changed_functions = extract_changed_functions_challenge_project(Path(args.challenge_project), args.file_extension)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'functions.json'), 'w') as f:
        json.dump(changed_functions, f)
    
if __name__ == '__main__':
    main()