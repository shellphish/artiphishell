#!/bin/bash

export AIXCC_LITELLM_HOSTNAME="http://wiseau.seclab.cs.ucsb.edu:666/"
export LITELLM_KEY="sk-artiphishell-da-best!!!"
export USE_LLM_API=1
export LANGSMITH_TRACING=true
export LANGSMITH_ENDPOINT="https://api.smith.langchain.com"
export LANGSMITH_API_KEY="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"
export LANGSMITH_PROJECT="pr-proper-lyre-88"

OSS_FUZZ=/home/sid/backups/backup-nginx-14742980643//patcherq.oss_fuzz_repo/536de375e20c4b3c804771d6b9fb433c
SOURCE=/home/sid/backups/backup-nginx-14742980643//patcherq.crs_tasks_analysis_source/536de375e20c4b3c804771d6b9fb433c
ID=4fb30dc37508c06a35e6728dae663658

TESTDIR=/home/sid/testenv
# if [ ! -d "$TESTDIR" ]; then
#     mkdir -p $TESTDIR
# fi

# # if the source-root directory does not exixt in TESTDIR, then copy it
# if [ ! -d "$TESTDIR/source-root" ]; then
#     cp -r $SOURCE $TESTDIR/source-root
# fi
# # if the oss-fuzz directory does not exist in TESTDIR, then copy it
# if [ ! -d "$TESTDIR/oss-fuzz" ]; then
#     cp -r $OSS_FUZZ $TESTDIR/oss-fuzz
# fi

python3 get_compile_flags.py --project_id $ID --source_root $SOURCE --target_root $OSS_FUZZ/projects/nginx \
        --local_run --bitcode /home/sid/griller-dataset/nginx/temp/nginx.bc --output_file cflags.txt
         