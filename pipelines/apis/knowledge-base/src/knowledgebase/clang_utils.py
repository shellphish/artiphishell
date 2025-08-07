import clang.cindex
import tempfile

from .shared_utils import CommitFile

try:
    clang.cindex.conf.set_library_file('/home/yigitcankaya/.virtualenvs/aixcc/lib/python3.8/site-packages/clang/native/libclang.so')
except ImportError:
    print('Could not import clang library...')

### utilities related to processing Linux kernel repo files
    
def read_file_lines(fname, ranges, actual_file_name=None):

    actual_file_name = fname if actual_file_name is None else actual_file_name

    with open(fname, 'r') as fp:
        lines = fp.read().split('\n')
    
    contents = {}
    for func, (start,end) in ranges.items():
        start_line,start_col = start
        end_line, end_col = end

        src = lines[start_line-1:end_line]

        # TODO -- very hacky solution to eliminate forward declared functions
        # solve this with clang.cindex

        if '{' not in src and '}' not in src:
            continue

        src[0] = src[0][start_col-1:].strip()
        src[-1] = src[-1][:end_col].strip()

        src = '\n'.join(src)

        contents[func] = {}
        contents[func]['range'] = [start_line, start_col, end_line, end_col]
        contents[func]['src'] =  src
        contents[func]['identifier'] = func
        contents[func]['signature'] = ' '.join(src[:src.find('{')].strip().split())
        contents[func]['full_name'] = f'{actual_file_name}::{func}' 
        contents[func]['access'] = 'N/A'
        contents[func]['return'] = ' '.join(src[:src.find(func)].strip().split())

    return contents

def find_functions(tu):
    ranges = {}
    for c in tu.cursor.walk_preorder():
        file = c.extent.start.file

        if not hasattr(file, 'name'):
            continue

        if tu.cursor.extent.start.file.name != file.name:
            continue

        if not c.is_definition():
            continue

        ck = clang.cindex.CursorKind
        if c.kind not in [ck.FUNCTION_DECL, ck.CXX_METHOD, ck.FUNCTION_TEMPLATE]:#, ck.DESTRUCTOR, ck.CONSTRUCTOR]:
            continue

        func_name = c.spelling
        start_line = c.extent.start.line
        start_column = c.extent.start.column
        end_line = c.extent.end.line
        end_column = c.extent.end.column

        ranges[func_name] = ((start_line, start_column), (end_line, end_column))

    return ranges

def get_functions_in_commit_file(repo, commit_sha, filepath):

    cf = CommitFile(repo, commit_sha, filepath, bytes=True)
    tf = tempfile.NamedTemporaryFile(delete=True, suffix=cf.extension)
    tf.write(cf.contents)

    index = clang.cindex.Index.create()
    tu = index.parse(tf.name, args=['-fparse-all-comments'], options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    ranges = find_functions(tu)
    contents = read_file_lines(tf.name, ranges, actual_file_name=filepath)
    tf.close()

    return contents