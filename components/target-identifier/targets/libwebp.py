import logging
import os
import re
from os.path import join

LOG = logging.getLogger(__name__)

EXPECTED_FILE_PATHS=['src/libwebp.pc.in', 'src/libwebpdecoder.pc.in']
EXPECTED_DIR_PATHS=['src/webp/']
def is_libwebp(root, dirs, files):
    # if 'webp' in root: import ipdb; ipdb.set_trace()
    if not {'configure.ac', 'makefile.unix'}.issubset(files):
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
    AC_INIT([libwebp], [1.4.0]
    '''
    version = re.search(r"AC_INIT\(\[libwebp\], \[(\d+)\.(\d+)\.(\d+)", data)

    if not version:
        LOG.warning(f"Failed to parse libwebp version from {root}")

    data = {}
    if version:
        data['version'] = f"{version.group(1)}.{version.group(2)}.{version.group(3)}"

    return data

