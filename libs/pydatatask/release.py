#!/usr/bin/env python3

from pathlib import Path
import re
import subprocess
import sys

import semver

package = "pydatatask"
canonical_branch = "main"
src = Path(__file__).parent / Path(package)
version_file = src / "__init__.py"
release_file = src / "__init__.py"
version_re = re.compile(r'(?P<prefix>^__version__ = ")(?P<version>.*)(?P<suffix>"$)', re.MULTILINE)
release_re = re.compile(r'(?P<prefix>^released_version = ")(?P<version>.*)(?P<suffix>"$)', re.MULTILINE)


def is_main_unchanged():
    branch = subprocess.check_output(
        ["git", "symbolic-ref", "HEAD"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if branch.decode().strip() != "refs/heads/" + canonical_branch:
        print(f"Must be on {canonical_branch} branch for release")
        return False
    status = subprocess.check_output(
        ["git", "status", "--porcelain"], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for line in status.splitlines():
        if line and not line.startswith(b"?? "):
            print("Repository is not clean")
            return False
    return True


def read_version_number(filename, regex):
    with open(filename, "r", encoding="utf-8") as fp:
        data = fp.read()
    match = regex.search(data)
    return match.group("version")


def write_version_number(filename, regex, version):
    with open(filename, "r", encoding="utf-8") as fp:
        data = fp.read()
    data_subbed = regex.sub(r"\g<prefix>" + version + r"\g<suffix>", data)
    with open(filename, "w", encoding="utf-8") as fp:
        fp.write(data_subbed)


def finalize():
    release_version = read_version_number(release_file, release_re)
    write_version_number(version_file, version_re, release_version)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("major", "minor", "patch", "finalize"):
        print(f"Usage: {sys.argv[0]} major|minor|patch|finalize")
        return 1

    if sys.argv[1] == "finalize":
        finalize()
        return 0

    if not is_main_unchanged():
        return 1

    prev_release_str = read_version_number(release_file, release_re)
    prev_version = semver.VersionInfo.parse(prev_release_str)
    if sys.argv[1] == "major":
        version = prev_version.bump_major()
    elif sys.argv[1] == "minor":
        version = prev_version.bump_minor()
    else:
        version = prev_version.bump_patch()

    release_str = str(version)
    version_str = str(version.next_version("prerelease", prerelease_token="dev"))

    write_version_number(release_file, release_re, release_str)
    write_version_number(version_file, version_re, version_str)
    subprocess.check_call(["git", "commit", "-am", f"Release {release_str}"])
    subprocess.check_call(["git", "tag", "-afm", f"Release {release_str}", "v" + release_str])
    subprocess.check_call(["git", "push", "--follow-tags"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
