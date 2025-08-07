import argparse
import glob
import hashlib
import json
import logging
import os
from concurrent.futures import ProcessPoolExecutor

import git
import jsonschema
from antlr4 import *
from tqdm import tqdm

from antlrlib import JavaParserVisitor, output_schema
from antlrlib.JavaLexer import JavaLexer
from antlrlib.JavaParser import JavaParser

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class JenkinsParser(JavaParserVisitor):
    def __init__(self):
        super().__init__()
        self._class = []
        self.current_package = ""

    def visitPackageDeclaration(self, ctx: JavaParser.PackageDeclarationContext):
        package_name = ctx.qualifiedName().getText()
        self.current_package = package_name

    def visitClassDeclaration(self, ctx: JavaParser.ClassDeclarationContext):
        _temp = {}
        class_name = ctx.identifier().getText()
        _temp["Class Name"] = class_name
        tokens = ctx.parser.getTokenStream()
        _decl = []
        class_declaration_text = ""

        # Capture class declaration
        for token_index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1):
            class_declaration_text += tokens.get(token_index).text
            _decl.append(tokens.get(token_index).text)
        _temp["Class Declaration"] = _decl

        _method = []

        for i in ctx.classBody().classBodyDeclaration():
            try:
                method_declaration = i.memberDeclaration().methodDeclaration()
                method_tokens = method_declaration.parser.getTokenStream()
                method_declaration_text = ""
                method_signature = ""
                arguments = []
                func_return_type = ""
                static_method = False
                func_calls = []
                local_variables = []

                # Check if the method is static
                if "static" in method_declaration.getText():
                    static_method = True

                # Capture method signature
                if method_declaration.typeTypeOrVoid() is not None:
                    func_return_type = method_declaration.typeTypeOrVoid().getText()
                    method_signature += func_return_type + " "
                method_signature += method_declaration.identifier().getText()
                if method_declaration.formalParameters() is not None:
                    method_signature += method_declaration.formalParameters().getText()
                    for param in method_declaration.formalParameters().formalParameterList().formalParameter():
                        param_datatype = param.typeType().getText()  # we don't save this rn. If required please add this to func metadata
                        param_name = param.variableDeclaratorId().getText()
                        arguments.append(param_name)

                # Capture method declaration text
                for token_index in range(method_declaration.start.tokenIndex, method_declaration.stop.tokenIndex + 1):
                    method_declaration_text += method_tokens.get(token_index).text
                    # Simple check to identify function calls (this is a placeholder and needs proper implementation)
                    if "()" in method_tokens.get(token_index).text:
                        func_calls.append(method_tokens.get(token_index).text.strip())

                # Capture local variables from method body
                if method_declaration.methodBody() and method_declaration.methodBody().block():
                    for block_stmt in method_declaration.methodBody().block().blockStatement():
                        if block_stmt.localVariableDeclaration():
                            for variable_declarator in block_stmt.localVariableDeclaration().variableDeclarators().variableDeclarator():
                                local_var_name = variable_declarator.variableDeclaratorId().getText()
                                local_variables.append(local_var_name)

                # Compute hash, method, class, statline, startcol, endline, endcol, stat_offset, end_offset
                statline = method_declaration.start.line
                startcol = method_declaration.start.column
                endline = method_declaration.stop.line
                endcol = method_declaration.stop.column
                stat_offset = method_declaration.start.start
                end_offset = method_declaration.stop.stop
                method_name = method_declaration.identifier().getText()

                # Construct full method signature and class name
                full_method_signature = f"{self.current_package}.{class_name}.{method_signature}"
                full_class_name = f"{self.current_package}.{class_name}"
                method_hash = hashlib.sha256(f'{full_method_signature}-{method_declaration_text}'.encode()).hexdigest()

                # Capture global variables involved in static methods
                _global_vars = []
                if static_method:
                    for member in ctx.classBody().classBodyDeclaration():
                        try:
                            if member.memberDeclaration().fieldDeclaration():
                                for field in member.memberDeclaration().fieldDeclaration().variableDeclarators().variableDeclarator():
                                    if "static" in member.getText():
                                        var_name = field.variableDeclaratorId().getText()
                                        var_decl = member.memberDeclaration().fieldDeclaration().getText()
                                        _global_vars.append({"name": var_name, "declaration": var_decl})
                        except AttributeError:
                            pass

                _method.append({
                    "hash": method_hash,
                    "code": method_declaration_text,
                    "signature": full_method_signature,
                    "start_line": statline,
                    "start_column": startcol,
                    "start_offset": stat_offset,
                    "end_line": endline,
                    "end_column": endcol,
                    "end_offset": end_offset,
                    "global_variables": _global_vars,
                    "func_return_type": func_return_type,
                    "arguments": arguments,
                    "local_variables": local_variables,
                    "class_name": full_class_name,
                    "funcname": method_name,
                    "func_calls_in_func_with_fullname": func_calls,
                    "java": {
                        "package": self.current_package,
                    }
                })
            except AttributeError:
                pass

        _temp["Method Declarations"] = _method
        self._class.append(_temp)


def read(file):
    input_file = InputStream(open(file, 'r').read())
    lexer = JavaLexer(input_file)
    stream = CommonTokenStream(lexer)
    parser = JavaParser(stream)
    tree = parser.compilationUnit()
    visitor = JenkinsParser()
    visitor.visit(tree)
    data = visitor._class
    return data


def process_file(file_path, target_source):
    try:
        if '.java' in file_path:
            relative_file_path = os.path.relpath(file_path, target_source)
            file_name = os.path.basename(file_path)
            info = read(file_path)
            results = []
            for entry in info:
                for method in entry.get("Method Declarations"):
                    method["filepath"] = relative_file_path
                    method["filename"] = file_name
                    method["comments"] = []  # TODO: Implement comment extraction
                    results.append(method)
            return results
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
    return []


def _get_changed_files(commit):
    changed_files = []
    commit_diff = commit.diff(commit.parents[0], create_patch=True) if commit.parents else commit.diff(git.NULL_TREE)
    for diff in commit_diff:
        # Handle added, modified, and renamed files
        if diff.a_path:
            paths = [diff.a_path]
            for path in paths:
                if path and ".java" in path:
                    changed_files.append(path)
    return changed_files


def _get_commit_ids(repo):
    logging.info("Starting to get commit IDs")
    commit_ids = [commit.hexsha for commit in tqdm(repo.iter_commits(), desc="Processing commits")]
    logging.info(f"Finished getting commit IDs: {len(commit_ids)} commits found")
    commit_ids.reverse()
    return commit_ids


def find_git_repos(base_path: str):
    git_repos = []
    for root, dirs, _ in os.walk(base_path):
        if '.git' in dirs:
            git_repos.append(root)
            # Optional: skip subdirectories of the current git repo
            dirs[:] = [d for d in dirs if d != '.git']
    return git_repos


def process_over_commits(target_source, output_dir):
    for _src_dir in find_git_repos(f"{target_source}/src/"):
        try:
            repo = git.Repo(_src_dir)
        except git.InvalidGitRepositoryError:
            logging.info(f"Invalid Git repository found at {_src_dir}. Skipping...")
            continue
        main_folder = f"{output_dir}"
        os.makedirs(main_folder, exist_ok=True)

        main_folder = os.path.join(main_folder, os.path.basename(_src_dir))
        os.makedirs(main_folder, exist_ok=True)

        commit_ids = _get_commit_ids(repo)
        unchanged_functions = set()
        if len(commit_ids) <= 1:
            continue

        for index, commit_id in enumerate(tqdm(commit_ids), 0):
            print(commit_id)
            repo.git.checkout(commit_id)
            changed_files = _get_changed_files(repo.commit(commit_id))
            changed_files = [f'{_src_dir}/{f}' for f in changed_files]

            commit_id_dir = f"{index}_{commit_id}"
            class_folder = os.path.join(main_folder, commit_id_dir, "class")
            method_folder = os.path.join(main_folder, commit_id_dir, "methods")
            macro_folder = os.path.join(main_folder, commit_id_dir, "macro")
            function_folder = os.path.join(main_folder, commit_id_dir, "function")
            if index > 0:
                os.makedirs(class_folder, exist_ok=True)
                os.makedirs(method_folder, exist_ok=True)
                os.makedirs(macro_folder, exist_ok=True)
                os.makedirs(function_folder, exist_ok=True)

            logging.info(f"Found #{len(changed_files)} of Java files to process on commit {commit_id}.")

            with ProcessPoolExecutor() as executor:
                results = list(executor.map(process_file, changed_files, [f"{target_source}/src"] * len(changed_files)),
                               )
            for file_results in results:
                for method in file_results:
                    try:
                        jsonschema.validate(instance=method, schema=output_schema)
                        if index == 0:
                            unchanged_functions.add(method.get('hash'))
                            continue
                        if method.get('hash') not in unchanged_functions:
                            with open(f"{method_folder}/{method.get('hash')}.json", 'w') as f:
                                json.dump(method, f)
                                f.write('\n')  # Ensure each method entry is on a new line
                            unchanged_functions.add(method.get('hash'))
                    except jsonschema.exceptions.ValidationError as e:
                        logging.error(f"Error validating json schema {method.get('signature')}: {e}")
                        raise e
                    except Exception as e:
                        logging.error(f"Error writing method {method.get('signature')} to file: {e}")
                        raise e


def process_all(target_source, output_dir):
    for _src_dir in glob.glob(f"{target_source}/src/*"):
        files = glob.glob(f"{_src_dir}/**/*.java", recursive=True)
        main_folder = f"{output_dir}"
        os.makedirs(main_folder, exist_ok=True)

        main_folder = os.path.join(main_folder, os.path.basename(_src_dir))
        os.makedirs(main_folder, exist_ok=True)

        class_folder = os.path.join(main_folder, "CLASS")
        method_folder = os.path.join(main_folder, "METHOD")
        macro_folder = os.path.join(main_folder, "MACRO")
        function_folder = os.path.join(main_folder, "FUNCTION")
        

        os.makedirs(class_folder, exist_ok=True)
        os.makedirs(method_folder, exist_ok=True)
        os.makedirs(macro_folder, exist_ok=True)
        os.makedirs(function_folder, exist_ok=True)

        logging.info(f"Found {len(files)} Java files to process.")

        with ProcessPoolExecutor() as executor:
            results = list(
                tqdm(executor.map(process_file, files, [f"{target_source}/src"] * len(files)), total=len(files)))

        for file_results in results:
            for method in file_results:
                try:
                    jsonschema.validate(instance=method, schema=output_schema)
                    with open(f"{method_folder}/{method.get('hash')}.json", 'w') as f:
                        json.dump(method, f)
                        f.write('\n')  # Ensure each method entry is on a new line
                        logging.info(f"File Write Completed: {method.get('signature')}")
                except jsonschema.exceptions.ValidationError as e:
                    logging.error(f"Error validating json schema {method.get('signature')}: {e}")
                    raise e
                except Exception as e:
                    logging.error(f"Error writing method {method.get('signature')} to file: {e}")
                    raise e