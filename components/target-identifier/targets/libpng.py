import logging
import os
import re
from os.path import join

LOG = logging.getLogger(__name__)

def is_libpng(root, dirs, files):

    # import ipdb; ipdb.set_trace()
    if not {'configure.ac', 'png.c', 'png.h', 'libpng-config.in'}.issubset(files):
        return None
    
    with open(join(root, "configure.ac")) as f:
        data = f.read()

    # find 'm4_define(pcre2_major, [xxxx])'
    '''
    PNGLIB_VERSION=1.6.44.git
    PNGLIB_MAJOR=1
    PNGLIB_MINOR=6
    PNGLIB_RELEASE=44
    '''
    major = re.search(r"PNGLIB_MAJOR=(\d+)", data)
    minor = re.search(r"PNGLIB_MINOR=(\d+)", data)
    release = re.search(r"PNGLIB_RELEASE=(\d+)", data)

    if not (major and minor and release):
        LOG.warning(f"Failed to parse libpng version from {root}: {major=}, {minor=}, {release=}")

    data = {}
    if major or minor or release:
        major = major or 'UNKNOWN'
        minor = minor or 'UNKNOWN'
        release = release or 'UNKNOWN'
        data['version'] = f"{major.group(1)}.{minor.group(1)}.{release.group(1)}"

    return data

