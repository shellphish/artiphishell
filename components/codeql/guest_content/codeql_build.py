#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
import json
# SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

argv = sys.argv[1:]

with open("/project.json", 'r') as f:
    project = json.load(f)

LANGUAGE = project['language'].lower()
LANGUAGE = subprocess.check_output(['/shellphish/to_codeql_lang.sh', LANGUAGE]).strip().lower()
    
DATABASE_DIR="/work/.sss-codeql-database"

# codeql database create \
#     "$DATABASE_DIR" \
#     --language "${LANGUAGE}" \
#     --command "${REAL_BUILD_SCRIPT}" \
#     --common-caches="/shellphish/.codeql-cache/"

print(f"Creating CodeQL database in {DATABASE_DIR} for language {LANGUAGE} with command {argv}")
os.execve('/codeql/codeql/codeql', [
    'codeql',
    'database',
    'create',
    DATABASE_DIR,
    '--language',
    LANGUAGE,
    '--threads',
    os.environ.get('NPROC_VAL', str(os.cpu_count())),
    '--common-caches=/shellphish/.codeql-cache/',
    '--command',
    # now, we have to convert the rest of argv into a single correctly shell escaped string to pass to --command safely
    shlex.join(argv)
], os.environ)
