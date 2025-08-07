import glob
import hashlib
import json
import logging
import os
import tempfile
import traceback
from multiprocessing import Pool, cpu_count
from pathlib import Path
import tempfile
import pickle
import shutil


import clang.cindex
import git
import joblib
import jsonschema
import tqdm
from joblib import Parallel, delayed
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .schema import output_schema
from ..db import FunctionInfo, MethodInfo, MacroInfo, Base

clang.cindex.Config.set_library_file("/usr/lib/x86_64-linux-gnu/libclang-17.so.17")
SUFFIX = ['.cpp', '.c', '.h', '.hpp', '.cc']  # TODO: maybe stuff like .C / .cc ?


# WARNING: diff-ranker needs this, don't touch it!!!

def collect_info_in_file(fpath):
    """
    functions include:
        * pure functions
        * c++ function templates
        * constructor/destructor
    methods include:
        * c++ methods
    macros include:
        * macro definitions
    """
    # TODO:
    #    * handle overloaded functions with the same name

    index = clang.cindex.Index.create()
    tu = index.parse(fpath, args=['-fparse-all-comments'],
                        options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD | clang.cindex.TranslationUnit.PARSE_INCOMPLETE | 0x8000)
    # Explaination of 0x8000: undocumented flag? search CXTranslationUnit_RetainExcludedConditionalBlocks in clang code for details
    info_list = []
    global_variables = []

    # Collect global variables
    for c in tu.cursor.walk_preorder():
        if c.kind == clang.cindex.CursorKind.VAR_DECL and c.semantic_parent == tu.cursor:
            # Check if the global variable is declared in the source file
            file = c.extent.start.file
            if file and file.name == fpath:
                # Global variable declaration
                declaration_tokens = [token.spelling for token in c.get_tokens()]
                declaration = ' '.join(declaration_tokens)
                global_variables.append({'name': c.spelling, 'declaration': declaration, 'usage': set()})
                # global_variables.append({'name': c.spelling, 'declaration': declaration, })
    # walk through all tokens in a module
    for c in tu.cursor.walk_preorder():
        # only deal with functions/methods/macros defined in the source file, not included files
        file = c.extent.start.file
        if not file or file.name != fpath:
            continue

        # deal with macros first
        if c.kind == clang.cindex.CursorKind.MACRO_DEFINITION:
            tokens = list(c.get_tokens())
            assert tokens

            # check whether this is a macro function
            # to be a macro function, it has to be defined in the following form
            # #define MACRO_NAME   (ARGS) ...stuff...
            # basically, a close parenthesis followed by something else and there should be no
            # parenthesis in the ARGS
            if len(tokens) == 1 or tokens[1].spelling != '(':
                signature = None
                continue
            else:
                tokens2 = [x.spelling for x in tokens[2:]]
                l_index = tokens2.index('(') if '(' in tokens2 else -1
                r_index = tokens2.index(')') if ')' in tokens2 else -1
                if 0 <= l_index < r_index:
                    signature = None
                elif r_index == len(tokens2) - 1:
                    signature = None
                else:
                    signature = ''.join([t.spelling for t in tokens[0:r_index + 1 + 2]])

            name = c.spelling

            # print(f"\t{name}: {c.kind}")

            src_path = fpath
            extent_kwargs = {
                'start_line': c.extent.start.line,
                'start_column': c.extent.start.column,
                'start_offset': c.extent.start.offset,
                'end_line': c.extent.end.line,
                'end_column': c.extent.end.column,
                'end_offset': c.extent.end.offset,
                'global_variables': ClangIndexer.get_used_globals(c, global_variables),
                # 'global_variables': global_variables
            }
            code = get_code(src_path, extent_kwargs['start_line'], extent_kwargs['end_line'])
            h = hashlib.md5(f"{name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
            info = MacroInfo(hash=h, name=name, signature=signature, src_path=src_path,
                                code=code, **extent_kwargs)
            info_list.append(info)
            continue

        # we don't care about function declarations
        if not c.is_definition():
            continue

        # we only care about function/method definitions
        ck = clang.cindex.CursorKind
        if c.kind not in [ck.FUNCTION_DECL, ck.CXX_METHOD, ck.FUNCTION_TEMPLATE, ck.DESTRUCTOR, ck.CONSTRUCTOR]:
            continue

        # append the result
        match c.kind:
            case ck.FUNCTION_DECL | ck.FUNCTION_TEMPLATE:
                name = get_full_name(c, fpath=fpath)

                # assert '::' not in name  # namespaced functions in C++ can have ::

                mangled_name = c.mangled_name  # there is no mangled_name for function template
                # print(f"\t{name}: {c.kind}")
                src_file = fpath
                signature = c.result_type.spelling + ' ' + c.displayname
                extent_kwargs = {
                    'start_line': c.extent.start.line,
                    'start_column': c.extent.start.column,
                    'start_offset': c.extent.start.offset,
                    'end_line': c.extent.end.line,
                    'end_column': c.extent.end.column,
                    'end_offset': c.extent.end.offset,
                    'global_variables': ClangIndexer.get_used_globals(c, global_variables)
                    # 'global_variables': global_variables
                }

                code = get_code(src_file, extent_kwargs['start_line'], extent_kwargs['end_line'])
                h = hashlib.md5(f"{name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
                info = FunctionInfo(hash=h, name=name, mangled_name=mangled_name, src_path=src_file,
                                    signature=signature,
                                    code=code, comment=c.raw_comment, calls=json.dumps(get_func_calls(c)),
                                    **extent_kwargs)

                info_list.append(info)
            case ck.CXX_METHOD | ck.DESTRUCTOR | ck.CONSTRUCTOR:
                full_name = get_full_name(c, fpath=fpath)
                # print(f"\t{full_name}: {c.kind}")

                assert '::' in full_name

                mangled_name = c.mangled_name  # there is no mangled_name for function template
                method_name = full_name.rsplit('::')[-1]
                src_file = fpath
                signature = c.result_type.spelling + ' ' + c.displayname

                extent_kwargs = {
                    'start_line': c.extent.start.line,
                    'start_column': c.extent.start.column,
                    'start_offset': c.extent.start.offset,
                    'end_line': c.extent.end.line,
                    'end_column': c.extent.end.column,
                    'end_offset': c.extent.end.offset,
                    'global_variables': ClangIndexer.get_used_globals(c, global_variables)
                    # 'global_variables': global_variables
                }
                code = get_code(src_file, extent_kwargs['start_line'], extent_kwargs['end_line'])
                h = hashlib.md5(
                    f"{mangled_name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
                info = MethodInfo(hash=h, full_name=full_name, method_name=method_name, mangled_name=mangled_name,
                                    src_path=src_file, signature=signature,
                                    code=code, comment=c.raw_comment, calls=json.dumps(get_func_calls(c)),
                                    **extent_kwargs)
                info_list.append(info)
            case _:
                raise NotImplementedError(f"Unknown cursor kind when processing function names: {c.kind}")

    return info_list

def prepend(c, name, fpath=None):
    # print("??", c.semantic_parent, c.semantic_parent.kind, c.semantic_parent.spelling)
    pc = c.semantic_parent
    ck = clang.cindex.CursorKind
    match pc.kind:
        case ck.TRANSLATION_UNIT:
            return pc, name
        case ck.NAMESPACE | ck.STRUCT_DECL | ck.CLASS_DECL | ck.CLASS_TEMPLATE:
            return pc, pc.spelling + "::" + name
        case ck.UNEXPOSED_DECL:
            """
            for extern function with weird definition, we ignore it
            """
            return pc, name
        case _:
            raise NotImplementedError(
                f"Unknown cursor kind when processing function names: {pc.kind} in {pc.spelling} with name {name} in file {fpath}")


def get_full_name(c, fpath=None):
    name = c.spelling
    while c.kind != clang.cindex.CursorKind.TRANSLATION_UNIT:
        c, name = prepend(c, name, fpath=fpath)
    # print("  =>", name)
    return name


def get_func_calls(c):
    calls = []
    for x in c.walk_preorder():
        if x.kind == clang.cindex.CursorKind.CALL_EXPR:
            children = list(x.get_children())
            func_name = x.spelling
            if not func_name:
                # sometimes clang knows the call is there but cant figure out the function name
                #   but it does give us the starting and ending byte index
                #   so we will parse it ourselfs =)
                #   e.g. doesn't know the name of tipc_crypto_key_rcv call in tipc_crypto_msg_rcv
                srcfile = x.location.file.name
                srcfile_start = x.extent.start.offset
                scrfile_end = x.extent.end.offset
                srcfile_contents = open(srcfile).read()
                function_call = srcfile_contents[srcfile_start:scrfile_end]
                func_name = function_call.split("(")[0]
            if children and children[0].kind == clang.cindex.CursorKind.MEMBER_REF_EXPR:
                calls.append(('CXX_METHOD', func_name))
            else:
                calls.append(('FUNCTION', func_name))
    return calls


def get_code(fpath, start, end):
    start -= 1
    end -= 1
    code = ''
    with open(fpath) as f:
        for i, line in enumerate(f):
            if start <= i <= end:
                code += line
            if i == end:
                break
    return code


class ClangIndexer:
    def __init__(self, src_dir, output, source_prefix='', threads=-1, output_mode="sqlite", force_output=False, dump_cache=False):
        self.src_dir = Path(os.path.realpath(src_dir))
        self.source_prefix = source_prefix
        self.output = Path(output)
        self.session = None
        self.mode = output_mode
        self.repo = None
        # setup threads
        if threads == -1:
            self.threads = round(int(os.environ.get("NPROC_VAL", cpu_count())) / 2.0)
        else:
            self.threads = threads

        if self.output.exists():
            shutil.rmtree(self.output, ignore_errors=True)
        if not self.output.exists():
            self.output.mkdir()

        self.function_dir = None
        self.method_dir = None
        self.macro_dir = None

        self.dump_cache = dump_cache

        # setup output
        # if self.mode == "json":
        #     # make dir strings
        #     self.function_dir = self.output / "FUNCTION"
        #     self.method_dir = self.output / "METHOD"
        #     self.macro_dir = self.output / "MACRO"
        #     # create output dirs
        #     if force_output:
        #         if self.output.exists():
        #             os.system(f"rm -rf {str(self.output)}")
        #     if not self.output.exists():
        #         self.output.mkdir()
        #     self.function_dir.mkdir()
        #     self.method_dir.mkdir()
        #     self.macro_dir.mkdir()

    def _save_info(self, info):
        if not info:
            return
        if self.mode == "sqlite":
            # session created here now because it can't serialize
            if not self.session:
                engine = create_engine(f'sqlite:///{str(self.output)}')
                Base.metadata.create_all(engine)
                Session = sessionmaker(bind=engine)
                self.session = Session()
                return

            # do not overwrite existing info
            # notice that the hash is calculated based on "name|code".
            # It is possible that a macro is defined twice in the same file, and we just
            # want one piece of the same information

            # exists = self.session.get(info.__class__, info.hash)
            # if not exists:
            self.session.add(info)
            self.session.commit()
        elif self.mode == "json":
            # get filename
            filename = Path(info.src_path).name
            # add generic fields to entry
            entry = {}
            entry["hash"] = info.hash
            entry["code"] = info.code
            entry["signature"] = info.signature
            entry["filename"] = filename
            entry["cfg"] = ""  # TODO: Fix
            entry["start_line"] = info.start_line
            entry["start_column"] = info.start_column
            entry["start_offset"] = info.start_offset
            entry["end_line"] = info.end_line
            entry["end_column"] = info.end_column
            entry["end_offset"] = info.end_offset
            # entry["code_wo_comments"] = info.code # TODO: Fix
            entry["global_variables"] = info.global_variables
            entry["local_variables"] = []  # TODO: Fix
            entry["func_return_type"] = ""  # TODO: Fix
            entry["arguments"] = []  # TODO: Fix
            entry["filepath"] = info.src_path

            # add specific fields for different info types
            outdir = self.output
            if type(info) == FunctionInfo:
                entry["funcname"] = info.name
                entry["full_funcname"] = info.name
                entry["func_calls_in_func_with_fullname"] = []
                entry["comments"] = [info.comment]  # TODO: Add rest of comments
                for (calltype, name) in json.loads(info.calls):
                    entry["func_calls_in_func_with_fullname"].append(name)
                outdir = self.function_dir
            elif type(info) == MethodInfo:
                entry["funcname"] = info.method_name
                entry["full_funcname"] = info.full_name
                entry["func_calls_in_func_with_fullname"] = []
                entry["comments"] = [info.comment]  # TODO: Add rest of comments
                for (calltype, name) in json.loads(info.calls):
                    entry["func_calls_in_func_with_fullname"].append(name)
                outdir = self.method_dir
            elif type(info) == MacroInfo:
                entry["funcname"] = info.name
                entry["full_funcname"] = info.name
                entry["func_calls_in_func_with_fullname"] = []
                entry["comments"] = []
                outdir = self.macro_dir
            else:
                raise Exception("Unknown info type")

            # save to file
            try:
                jsonschema.validate(instance=entry, schema=output_schema)
            except jsonschema.exceptions.ValidationError as e:
                logging.error(f"Error validating json schema: {e}")
                raise e
            else:
                assert isinstance(outdir, Path)
                outfile = outdir / (f'{entry["funcname"]}_{filename}_{info.hash}.json')
                tmp = tempfile.NamedTemporaryFile(delete=False, mode="w")
                json.dump(entry, tmp)
                Path(tmp.name).rename(outfile)

    def _save_all(self, info):
        for x in info:
            self._save_info(x)

    @staticmethod
    def _find_src_files(src_dir, source_prefix):
        """
        find all files with the listed suffix in the source directory
        """
        files = [glob.glob(str(Path(src_dir) / source_prefix / '**' / f'*{s}'), recursive=True) for s in SUFFIX]
        # for f in sum(files, []):
        #    print(f)
        return set(sum(files, []))

    @staticmethod
    def get_used_globals(cursor, global_vars):
        used_globals = set()
        for token in cursor.get_tokens():
            for var in global_vars:
                if token.spelling == var['name']:
                    used_globals.add(var['name'])
                    var['usage'].add(cursor.spelling)
        return [{'declaration': var['declaration'], 'name': var['name']} for var in global_vars if
                var['name'] in used_globals]

    def _resolve_path(self, path):
        resolved_path = Path(path).resolve(strict=True)
        return os.path.relpath(str(resolved_path), f'{self.src_dir}/src/')

    def collect_info_in_file(self, fpath):
        """
        functions include:
            * pure functions
            * c++ function templates
            * constructor/destructor
        methods include:
            * c++ methods
        macros include:
            * macro definitions
        """
        # TODO:
        #    * handle overloaded functions with the same name

        # use cache if available
        with open(fpath, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
            # just in case we have too many files that breaks the fs
            cache_path = f"/clang-indexer-cache/{file_hash[0:2]}/{file_hash[2:4]}/{file_hash[4:]}.pickle"
            
            if os.path.exists(cache_path):
                with open(cache_path, 'rb') as f:
                    return pickle.load(f)

        index = clang.cindex.Index.create()
        tu = index.parse(fpath, args=['-fparse-all-comments'],
                         options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD | clang.cindex.TranslationUnit.PARSE_INCOMPLETE | 0x8000)
        # Explaination of 0x8000: undocumented flag? search CXTranslationUnit_RetainExcludedConditionalBlocks in clang code for details
        info_list = []
        global_variables = []

        for c in tu.cursor.walk_preorder():
            file = c.extent.start.file
            if not file or file.name != fpath:
                continue
            if c.kind == clang.cindex.CursorKind.VAR_DECL and c.semantic_parent == tu.cursor:
                # Global variable declaration
                declaration_tokens = [token.spelling for token in c.get_tokens()]
                declaration = ' '.join(declaration_tokens)
                global_variables.append({'name': c.spelling, 'declaration': declaration, 'usage': set()})
                # global_variables.append({'name': c.spelling, 'declaration': declaration, })
                continue
            # deal with macros first
            if c.kind == clang.cindex.CursorKind.MACRO_DEFINITION:
                tokens = list(c.get_tokens())
                assert tokens

                # check whether this is a macro function
                # to be a macro function, it has to be defined in the following form
                # #define MACRO_NAME   (ARGS) ...stuff...
                # basically, a close parenthesis followed by something else and there should be no
                # parenthesis in the ARGS
                if len(tokens) == 1 or tokens[1].spelling != '(':
                    signature = None
                    continue
                else:
                    tokens2 = [x.spelling for x in tokens[2:]]
                    l_index = tokens2.index('(') if '(' in tokens2 else -1
                    r_index = tokens2.index(')') if ')' in tokens2 else -1
                    if 0 <= l_index < r_index:
                        signature = None
                    elif r_index == len(tokens2) - 1:
                        signature = None
                    else:
                        signature = ''.join([t.spelling for t in tokens[0:r_index + 1 + 2]])

                name = c.spelling

                # print(f"\t{name}: {c.kind}")

                src_path = fpath
                extent_kwargs = {
                    'start_line': c.extent.start.line,
                    'start_column': c.extent.start.column,
                    'start_offset': c.extent.start.offset,
                    'end_line': c.extent.end.line,
                    'end_column': c.extent.end.column,
                    'end_offset': c.extent.end.offset,
                    'global_variables': ClangIndexer.get_used_globals(c, global_variables),
                    # 'global_variables': global_variables
                }
                code = get_code(src_path, extent_kwargs['start_line'], extent_kwargs['end_line'])
                h = hashlib.md5(f"{name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
                info = MacroInfo(hash=h, name=name, signature=signature, src_path=self._resolve_path(src_path),
                                 code=code, **extent_kwargs)
                info_list.append(info)
                continue

            # we don't care about function declarations
            if not c.is_definition():
                continue

            # we only care about function/method definitions
            ck = clang.cindex.CursorKind
            if c.kind not in [ck.FUNCTION_DECL, ck.CXX_METHOD, ck.FUNCTION_TEMPLATE, ck.DESTRUCTOR, ck.CONSTRUCTOR]:
                continue

            # append the result
            match c.kind:
                case ck.FUNCTION_DECL | ck.FUNCTION_TEMPLATE:
                    name = get_full_name(c, fpath=fpath)

                    # assert '::' not in name  # namespaced functions in C++ can have ::

                    mangled_name = c.mangled_name  # there is no mangled_name for function template
                    # print(f"\t{name}: {c.kind}")
                    src_file = fpath
                    signature = c.result_type.spelling + ' ' + c.displayname
                    extent_kwargs = {
                        'start_line': c.extent.start.line,
                        'start_column': c.extent.start.column,
                        'start_offset': c.extent.start.offset,
                        'end_line': c.extent.end.line,
                        'end_column': c.extent.end.column,
                        'end_offset': c.extent.end.offset,
                        'global_variables': ClangIndexer.get_used_globals(c, global_variables)
                        # 'global_variables': global_variables
                    }

                    code = get_code(src_file, extent_kwargs['start_line'], extent_kwargs['end_line'])
                    h = hashlib.md5(f"{name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
                    info = FunctionInfo(hash=h, name=name, mangled_name=mangled_name, src_path=self._resolve_path(src_file),
                                        signature=signature,
                                        code=code, comment=c.raw_comment, calls=json.dumps(get_func_calls(c)),
                                        **extent_kwargs)

                    info_list.append(info)
                case ck.CXX_METHOD | ck.DESTRUCTOR | ck.CONSTRUCTOR:
                    full_name = get_full_name(c, fpath=fpath)
                    # print(f"\t{full_name}: {c.kind}")

                    assert '::' in full_name

                    mangled_name = c.mangled_name  # there is no mangled_name for function template
                    method_name = full_name.rsplit('::')[-1]
                    src_file = fpath
                    signature = c.result_type.spelling + ' ' + c.displayname

                    extent_kwargs = {
                        'start_line': c.extent.start.line,
                        'start_column': c.extent.start.column,
                        'start_offset': c.extent.start.offset,
                        'end_line': c.extent.end.line,
                        'end_column': c.extent.end.column,
                        'end_offset': c.extent.end.offset,
                        'global_variables': ClangIndexer.get_used_globals(c, global_variables)
                        # 'global_variables': global_variables
                    }
                    code = get_code(src_file, extent_kwargs['start_line'], extent_kwargs['end_line'])
                    h = hashlib.md5(
                        f"{mangled_name}|{code}|{extent_kwargs['global_variables']}".encode()).digest().hex()
                    info = MethodInfo(hash=h, full_name=full_name, method_name=method_name, mangled_name=mangled_name,
                                      src_path=self._resolve_path(src_file), signature=signature,
                                      code=code, comment=c.raw_comment, calls=json.dumps(get_func_calls(c)),
                                      **extent_kwargs)
                    info_list.append(info)
                case _:
                    raise NotImplementedError(f"Unknown cursor kind when processing function names: {c.kind}")

        if self.dump_cache and not os.path.exists(cache_path):
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, 'wb') as f:
                pickle.dump(info_list, f)

        return info_list

    def _collect_info_and_save(self, fpath):
        info = []
        # print(f"Processing: {fpath}")
        try:
            info = self.collect_info_in_file(fpath)
        except Exception as e:
            print("\n")
            print(f"Failed to parse: {fpath}")
            print("File contents:")
            print("\n")
            with open(fpath, "rb") as fd:
                print(fd.read())
            print("\n")
            traceback.print_exception(e)
            print("\n")
        return info

    def _collect_info_and_actually_save(self, fpath):
        info = self._collect_info_and_save(fpath)
        self._save_all(info)

    def _get_changed_files(self, commit: git.Commit):
        changed_files = []
        commit_diff = commit.diff(commit.parents[0], create_patch=True) if commit.parents else commit.diff(
            git.NULL_TREE)
        for diff in commit_diff:
            if diff.a_path:
                paths = [diff.a_path]
                for path in paths:
                    if path and any(path.endswith(suffix) for suffix in SUFFIX):
                        changed_files.append(path)
        return changed_files

    def _get_commit_ids(self):
        logging.info("Starting to get commit IDs")
        commit_ids = [commit.hexsha for commit in tqdm.tqdm(self.repo.iter_commits(), desc="Processing commits")]
        logging.info(f"Finished getting commit IDs: {len(commit_ids)} commits found")
        commit_ids.reverse()
        return commit_ids

    def _checkout_commit(self, commit_id):
        logging.info(f"checkout to commit: {commit_id}")
        self.repo.git.checkout(commit_id)
        assert commit_id == self.repo.commit().hexsha
        logging.info(f"checkout to commit: {self.repo.commit().hexsha} done")

    def run(self):
        for _src_dir in glob.glob(f'{self.src_dir}/src/*'):
            src_files = self._find_src_files(src_dir=_src_dir, source_prefix=self.source_prefix)

            print(f"Creating index of {len(src_files)} source files...")

            _source_git_project = _src_dir.split('/')[-1]

            _output = self.output
            self.output = self.output / _source_git_project
            if not self.output.exists():
                self.output.mkdir()

            self.function_dir = self.output / "FUNCTION"
            self.method_dir = self.output / "METHOD"
            self.macro_dir = self.output / "MACRO"

            self.function_dir.mkdir(exist_ok=True)
            self.method_dir.mkdir(exist_ok=True)
            self.macro_dir.mkdir(exist_ok=True)

            # Gather function info
            # TODO: Look into the "chunksize" argument in imap_unordered to increase speed
            # chunksize = max(min(256, len(src_files) // (self.threads * 4)), 20)
            # with Pool(processes=self.threads) as p:
            #     for func_infos in tqdm.tqdm(
            #             p.imap_unordered(self._collect_info_and_save, src_files, chunksize=chunksize),
            #             total=len(src_files)):
            #         self._save_all(func_infos)
            with joblib.parallel_backend('loky', n_jobs=int(os.environ.get("NPROC_VAL", cpu_count()))):
                Parallel(n_jobs=self.threads)(
                    delayed(self._collect_info_and_actually_save)(splitter) for splitter in src_files
                )
            self.output = _output

        print("Done!")

    def run_on_commit(self):
        for _src_dir in glob.glob(f'{self.src_dir}/src/*'):
            try:
                self.repo = git.Repo(_src_dir)
            except git.exc.InvalidGitRepositoryError:
                continue
            unchanged_functions = set()
            commits = self._get_commit_ids()
            _output_backup = self.output
            _source_git_project = _src_dir.split('/')[-1]
            self.output = self.output / _source_git_project
            if not self.output.exists():
                self.output.mkdir()
            for index, commit_id in enumerate(tqdm.tqdm(commits[1:]), 1):
                # print(f"Processing commit: {commit_id}")
                commit_id_dir = f"{index}_{commit_id}"

                self._checkout_commit(commit_id)
                commit = self.repo.commit(commit_id)

                changed_files = list(map(lambda x: f'{_src_dir}/{x}', self._get_changed_files(commit)))

                prev_commit = self.repo.commit(f'{commit_id}~1')

                # Get the versions of the files in the previous commit
                history_change_files = {}
                for file in changed_files:
                    rel_file_path = os.path.relpath(file, _src_dir)
                    try:
                        prev_version = prev_commit.tree / rel_file_path
                        temp_file_path = os.path.join(tempfile.gettempdir(), rel_file_path)
                        os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
                        with open(temp_file_path, 'wb') as temp_file:
                            temp_file.write(prev_version.data_stream.read())
                            history_change_files[rel_file_path] = temp_file_path
                    except KeyError as e:
                        history_change_files[rel_file_path] = None
                        # raise KeyError(
                        #     f"Error processing file {rel_file_path}: {str(e)}, runnning on commit {commit_id}, "
                        #     f"is not found on previous commit {prev_commit.hexsha}")
                        # no need to raise, purpose of exception got is to check if the file
                        # is newly introduced in this commit
                chunksize = max(min(256, len(history_change_files) // (self.threads * 4)), 20)
                with Pool(processes=self.threads) as p:
                    for func_infos in tqdm.tqdm(
                            p.imap_unordered(self._collect_info_and_save,
                                             list(filter(lambda x: x != None, history_change_files.values())),
                                             chunksize=chunksize)):
                        for func_info in func_infos:
                            unchanged_functions.add(func_info.hash)

                _output = self.output
                _function_dir = self.function_dir
                _method_dir = self.method_dir
                self.output = self.output / commit_id_dir
                if not self.output.exists():
                    self.output.mkdir()
                self.function_dir = self.output / "FUNCTION"
                self.method_dir = self.output / "METHOD"
                self.macro_dir = self.output / "MACRO"
                # create output dirs

                self.function_dir.mkdir()
                self.method_dir.mkdir()
                self.macro_dir.mkdir()

                # Gather function info
                print(f'running on commit {commit_id}...')
                chunksize = max(min(256, len(changed_files) // (self.threads * 4)), 20)
                with Pool(processes=self.threads) as p:
                    for func_infos in tqdm.tqdm(
                            p.imap_unordered(self._collect_info_and_save, changed_files, chunksize=chunksize)):
                        for func_info in func_infos:
                            if func_info.hash not in unchanged_functions:
                                self._save_info(func_info)
                                unchanged_functions.add(func_info.hash)
                        # self._save_all(func_infos)
                self.output = _output
                self.function_dir = _function_dir
                self.method_dir = _method_dir
            self.output = _output_backup
            print("Done!")
