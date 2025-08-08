import logging
import os
import re
from os.path import join, abspath
import subprocess

LOG = logging.getLogger(__name__)

EXPECTED_FILE_PATHS=['lib/gif_lib.h', 'lib/gif_err.c']
EXPECTED_DIR_PATHS=[]
def is_giflib_old(root, dirs, files):
    # if 'webp' in root: import ipdb; ipdb.set_trace()
    if not {'configure.ac'}.issubset(files):
        return None

    for file in EXPECTED_FILE_PATHS:
        if not os.path.isfile(join(root, file)):
            return None

    for dir in EXPECTED_DIR_PATHS:
        if not os.path.isdir(join(root, dir)):
            return None

    with open(join(root, "configure.ac")) as f:
        data = f.read()

    '''
    AC_INIT(giflib, [5.1.4], [esr@thyrsus.com], giflib)
    '''
    version = re.search(r"AC_INIT\(giflib, \[(\d+)\.(\d+)\.(\d+)", data)

    if not version:
        LOG.warning(f"Failed to parse libwebp version from {root}")

    data = {}
    data['structure'] = 'old'
    if version:
        data['version'] = f"{version.group(1)}.{version.group(2)}.{version.group(3)}"

    return data

def is_giflib_new(root, dirs, files):
    # if 'webp' in root: import ipdb; ipdb.set_trace()
    if not {'dgif_lib.c', 'egif_lib.c', 'gif_lib.h', 'getversion'}.issubset(files):
        return None

    os.chmod(join(root, "getversion"), 0o755)
    version = subprocess.check_output([abspath(join(root, "getversion"))], cwd=root).decode('utf-8').strip()

    if not version:
        LOG.warning(f"Failed to parse libwebp version from {root}")

    data = {}
    data['structure'] = 'new'
    if version:
        data['version'] = version

    return data
