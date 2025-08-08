import logging
import os
import re
from os.path import join

LOG = logging.getLogger(__name__)

EXPECTED_ROOT_FILES = {'z3.pc.cmake.in', 'CMakeLists.txt'}
EXPECTED_ROOT_DIRS = {'src'}
EXPECTED_FILE_PATHS=[]
EXPECTED_DIR_PATHS=['src/sat', 'src/solver', 'src/tactic']

def is_z3(root, dirs, files):
    # if 'webp' in root: import ipdb; ipdb.set_trace()
    if not EXPECTED_ROOT_FILES.issubset(files):
        return None
    if not EXPECTED_ROOT_DIRS.issubset(dirs):
        return None
    
    for file in EXPECTED_FILE_PATHS:
        if not os.path.isfile(join(root, file)):
            return None

    for dir in EXPECTED_DIR_PATHS:
        if not os.path.isdir(join(root, dir)):
            return None

    with open(join(root, "CMakeLists.txt")) as f:
        data = f.read()

    '''
project(Z3 VERSION 4.8.12.0 LANGUAGES CXX)
    '''
    version = re.search(r"project\(Z3\s+VERSION (\d+)\.(\d+)\.(\d+)", data.replace('\n', ' '))

    if not version:
        LOG.warning(f"Failed to parse z3 version from {root}")

    data = {}
    if version:
        data['version'] = f"{version.group(1)}.{version.group(2)}.{version.group(3)}"

    return data

