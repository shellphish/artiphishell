import logging
import os
import re
from os.path import join

LOG = logging.getLogger(__name__)

def is_pcre2(root, dirs, files):

    # import ipdb; ipdb.set_trace()
    if not {'src'}.issubset(dirs):
        return None
    
    if not {'configure.ac'}.issubset(files):
        return None
    
    if not os.path.isfile(join(root, 'src/pcre2.h.in')):
        return None
    
    with open(join(root, "configure.ac")) as f:
        data = f.read()

    # find 'm4_define(pcre2_major, [xxxx])'
    major = re.search(r"m4_define\(pcre2_major,\s+\[(\d+)\]\)", data)
    minor = re.search(r"m4_define\(pcre2_minor,\s+\[(\d+)\]\)", data)
    prerelease = re.search(r"m4_define\(pcre2_prerelease,\s+\[(.+)\]\)", data)
    date = re.search(r"m4_define\(pcre2_date,\s+\[(.+)\]\)", data)

    if not (major and minor and prerelease and date):
        LOG.warning(f"Failed to parse pcre2 version from {root}: {major=}, {minor=}, {prerelease=}, {date=}")
    
    '''
    m4_define(libpcre2_8_version,     [12:0:12])
    m4_define(libpcre2_16_version,    [12:0:12])
    m4_define(libpcre2_32_version,    [12:0:12])
    m4_define(libpcre2_posix_version, [3:5:0])
    '''
    libpcre2_8_version = re.search(r"m4_define\(libpcre2_8_version,\s+\[(.*)\]\)", data)
    libpcre2_16_version = re.search(r"m4_define\(libpcre2_16_version,\s+\[(\d+:\d+:\d+)\]\)", data)
    libpcre2_32_version = re.search(r"m4_define\(libpcre2_32_version,\s+\[(\d+:\d+:\d+)\]\)", data)
    libpcre2_posix_version = re.search(r"m4_define\(libpcre2_posix_version,\s+\[(\d+:\d+:\d+)\]\)", data)

    if not (libpcre2_8_version and libpcre2_16_version and libpcre2_32_version and libpcre2_posix_version):
        LOG.warning(f"Failed to parse pcre2 version from {root}: {libpcre2_8_version=}, {libpcre2_16_version=}, {libpcre2_32_version=}, {libpcre2_posix_version=}")

    data = {}
    if major or minor or prerelease:
        major = major or 'UNKNOWN'
        minor = minor or 'UNKNOWN'
        prerelease = prerelease or 'UNKNOWN'
        data['version'] = f"{major.group(1)}.{minor.group(1)}{prerelease.group(1)}"
    
    if date:
        data['date'] = date.group(1)
    if libpcre2_8_version:
        data['libpcre2_8_version'] = libpcre2_8_version.group(1)
    if libpcre2_16_version:
        data['libpcre2_16_version'] = libpcre2_16_version.group(1)
    if libpcre2_32_version:
        data['libpcre2_32_version'] = libpcre2_32_version.group(1)
    if libpcre2_posix_version:
        data['libpcre2_posix_version'] = libpcre2_posix_version.group(1)
    return data
