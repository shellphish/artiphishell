#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
import json

argv = sys.argv[1:]

DATABASE_DIR="/work/.sss-codeql-database"
DATABASE_DIR_NO_BUILD="/work/.sss-codeql-database-no-build"
# print the environemnt variables

LANGUAGE=None
language = os.environ["FUZZING_LANGUAGE"].strip()
if language == "c++" or language == "c":
    LANGUAGE="cpp"
elif language == "jvm" or language == "java":
    LANGUAGE="java"
else:
    print(f"No language found")
    exit(-1)

# codeql database create \
#     "$DATABASE_DIR" \
#     --language "${LANGUAGE}" \
#     --command "${REAL_BUILD_SCRIPT}" \
#     --common-caches="/shellphish/.codeql-cache/"

if LANGUAGE == "java":
    print(f"🚀 Creating CodeQL database in {DATABASE_DIR_NO_BUILD} for language {LANGUAGE}")
    subprocess.run(['/shellphish/codeql/codeql', 
        'database',
        'create',
        DATABASE_DIR_NO_BUILD,
        '--language',
        LANGUAGE,
        "--overwrite",
        '--threads',
        os.environ.get('NPROC_VAL', str(os.cpu_count())),
        '--build-mode',
        'none'
    ], check=True, env=os.environ)
print(f"🚀 Creating CodeQL database in {DATABASE_DIR} for language {LANGUAGE} with command {argv}")
os.execve('/shellphish/codeql/codeql', [
    'codeql',
    'database',
    'create',
    DATABASE_DIR,
    '--language',
    LANGUAGE,
    "--overwrite",
    '--threads',
    os.environ.get('NPROC_VAL', str(os.cpu_count())),
    '--command',
    # now, we have to convert the rest of argv into a single correctly shell escaped string to pass to --command safely
    shlex.join(argv)
], os.environ)