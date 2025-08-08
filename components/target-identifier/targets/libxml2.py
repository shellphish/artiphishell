import logging
import os
import re
from os.path import join

LOG = logging.getLogger(__name__)

def is_libxml2(root, dirs, files):

    # import ipdb; ipdb.set_trace()
    if not {'configure.ac', 'libxml.h', 'parser.c', 'xmlreader.c'}.issubset(files):
        return None
    
    with open(join(root, "configure.ac")) as f:
        data = f.read()

    # find 'm4_define(pcre2_major, [xxxx])'
    major = re.search(r"m4_define\(\[MAJOR_VERSION\],\s+(\d+)\)", data)
    minor = re.search(r"m4_define\(\[MINOR_VERSION\],\s+(\d+)\)", data)
    micro = re.search(r"m4_define\(\[MICRO_VERSION\],\s+(.+)\)", data)

    if not (major and minor and micro):
        LOG.warning(f"Failed to parse libxml2 version from {root}: {major=}, {minor=}, {micro=}")
        
    data = {}
    if major or minor or micro:
        major = major or 'UNKNOWN'
        minor = minor or 'UNKNOWN'
        micro = micro or 'UNKNOWN'
        data['version'] = f"{major.group(1)}.{minor.group(1)}.{micro.group(1)}"
    return data
