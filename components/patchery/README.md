# PatcherY
PatcherY is the next-generation [Patcherex](https://github.com/angr/patcherex), targeting source code and buildable
projects. 

## Installation
In a normal scenario, you can just install using the pip package:
```bash
pip install -e .
```

However, for AIxCC development, you should also run the setup script in the root of this directory:
```bash
./setup.sh
```

This will copy down the tests-data repo, build the local container, and make symlinks to the data.
The size of the container is around ~8GB, so make sure you have enough space.

To understand how to develop and test effectively, please refer to the [Developing](#developing) section.


## AIxCC Usage (independent) 
Normal runs from the command line look something like this:
```bash 
patchery --generate-verified-patch \
  --src-root ./tests/targets/hamlin/challenge/src/ \
  --run-script ./tests/targets/hamlin/challenge/run.sh \
  --lang "C++" \
  --report-file ./tests/reports/hamlin_report.txt \
  ...
  --output-path "./output.patch"
```

The best way to understand how to run it is looking at the [test_aicc.py](/tests/test_aicc.py) file.

### Linux Example
Most of the AICC targets supported can be found as a single end-to-end test in the [test_aicc.py](/tests/test_aicc.py) file.
As an example, you can run just the nginx exemplar test with:
```bash
pytest tests/test_aicc.py::TestPatcheryAICC::test_nginx_exemplar -s 
```

### OSS-FUZZ Example
```bash
export ENABLE_LLM_ANALYZER=1
export OSS_FUZZ_TARGET=1
export AGENTLIB_SAVE_FILES=0
pytest tests/test_ossfuzz.py::TestPatcheryOssFuzz::test_ossfuzz_xs_47443 -s -v
```

This will take around 10 mins to run with all verification steps.
An example of the output is:
```
DEBUG | 2024-06-11 04:07:30,159 | patchery.patcher | 🤖 Starting the 1/10 run ...
DEBUG | 2024-06-11 04:07:30,159 | patchery.patcher | Generating patch 1/1...
DEBUG | 2024-06-11 04:07:30,159 | patchery.generator.llm_patch_generator | 🔍 Generating patch...
DEBUG | 2024-06-11 04:07:30,259 | patchery.generator.llm_patch_generator | 💭 Prompting with prompt len=36505
DEBUG | 2024-06-11 04:07:47,520 | patchery.generator.llm_patch_generator | 💭 Proposed patch: <Patch: T16A314213F278F24033FD319656B88444973290B89B280E9722294778667407ED2ACB52>
DEBUG | 2024-06-11 04:07:47,793 | patchery.generator.llm_patch_generator | ✅  Diff successfully generated:
diff --git a/net/tipc/crypto.c b/net/tipc/crypto.c
index 24b78d9d0..dfbb94d23 100644
--- a/net/tipc/crypto.c
+++ b/net/tipc/crypto.c
@@ -2305,6 +2305,13 @@ static bool tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)
                goto exit;
        }

+       /* Check key length to avoid buffer overflow */
+       if (unlikely(keylen > size - (TIPC_AEAD_ALG_NAME + sizeof(__be32)))) {
+               pr_err("%s: key length is too large\n", rx->name);
+               kfree(skey); /* Free the allocated memory to prevent memory leak */
+               goto exit;
+       }
+
        /* Copy key from msg data */
        skey->keylen = keylen;
        memcpy(skey->alg_name, data, TIPC_AEAD_ALG_NAME);

INFO | 2024-06-11 04:07:47,793 | patchery.verifier.patch_verifier | 🔬 Running CompileVerificationPass now...
INFO | 2024-06-11 04:08:04,898 | patchery.verifier.patch_verifier | ✅ CompileVerificationPass passed
...
```

## Patch Ranking
PatcherY uses a ranking system to determine the best patch in the presence of multiple verified patches.
To use the ranker, you can run the following command:
```bash
patchery --continuous-ranking \
  --rank-patches /mock_cp/resources/patches/ \
  --rank-output-dir /mock_cp/resources/patches/ \
  --rank-timeout 10 --rank-wait-time 3
```

This runs the ranker in a loop for a max of `10` seconds and an in-loop wait for `3` seconds.
This will have output on stdout like so, every `3` seconds:
```
INFO     | 2024-07-04 21:06:55,663 | patchery.ranker.patch_ranker | Ranking output written to patch_ranks_1720152415.json
...
```

The output format looks like this:
```json
{
  "ranks": [
    "/mock_cp/resources/patches/patch.sdasda", 
    "/mock_cp/resources/patches/patch.aaaaaa"
  ], 
  "invalidated_patches": [], 
  "patch_info": {
    "/mock_cp/resources/patches/patch.sdasda": 7.467698726104354, 
    "/mock_cp/resources/patches/patch.aaaaaa": 8.622736323949841
  }, 
  "timestamp": 1720152415
}
```

## Developing
To develop/debug PatcherY, you must first have run the setup script:
```bash
./setup.sh
```

You should now have the test data in `./artiphishell-tests-data` that will get linked to testing directories.
To verify that your setup is correct, run the nginx exemplar test:
```bash
pytest tests/test_aicc.py::TestPatcheryAICC::test_nginx_exemplar -s 
```

This should take around 5 mins to run and should produce a verified patch.

The way PatcherY testcases work is the following:
1. You run `pytest` 
2. The testcase will start a container based on `aixcc-patchery` image and mount the test data
3. The command that is normally run in the artiphishell is run in the container

### Debugging
To debug, you want to first set a breakpoint in some code in PatcherY. For instance, you
can set it in the beginning of the `patchery/patcher.py` file by adding this line:
```python
breakpoint()
```

Now run the testcase you want to debug with the `DEBUG` variable:
```bash
DEBUG=1 pytest tests/test_aicc.py::TestPatcheryAICC::test_nginx_exemplar -s 
```

This will start the container the test runs in and break right before the PatcherY command is run.
It will print out the instructions that look something like this:
```md
=====================================
# Copy and run the following command in another terminal:
docker exec -it c5c1cb8a9e2d568bf299aeeb87c490e3d01f2ce31386eca13e9e0ff824387ae9 /bin/bash -c 'patchery --generate-aixcc-patch --target-root /home/mahaloz/github/artiphishell/components/patchery/tests/tmp/patchery/tmp3d74k79__target --alerting-inputs /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/crashing_seeds --patch-output-dir /home/mahaloz/github/artiphishell/components/patchery/tests/tmp/patchery/tmp3d74k79__target/patches --patch-meta-output-dir /home/mahaloz/github/artiphishell/components/patchery/tests/tmp/patchery/tmp3d74k79__target/patches_meta --raw-report /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/report.yaml --sanitizer-string "AddressSanitizer: heap-buffer-overflow" --function-json-dir /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/function_out_dir --function-indices /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/function_indices.json --functions-by-commit-jsons-dir /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/functions_by_commits --indices-by-commit /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/commit_indices.json --report-yaml /patchery/tests/aicc_testing/nginx/backup_4657771bd193f7185e973c773a547161_0/poi.yaml --crashing-commit 8e2a8e613fe5b6f03cb8e0c27180a468671f03a8 '
=====================================
```

Copy and paste this command into another terminal and run it. You will now in that terminal be broken where you set
the earlier breakpoint. When you are done, simply `exit` in both terminals.

### Adding a new testcase
To add a new testcase you first need to acquire a backup of the target you want to test.
Assuming you have the backup in `/tmp/backup.tar.gz`, you can do the following:
1. Make a new directory in `tests/aicc_testing/` with the name of your target (if it's new)
```bash
mkdir tests/aicc_testing/my_target
```

2. Convert the backup to the mini-format for PatcherY. This will output something like `backup_abcdefg1234567_0`.
```bash
./scripts/backup_to_testfiles.py --backup /tmp/backup.tar.gz --output ./tests/aicc_testing/my_target/
```

3. Make a new pytest testcase in `test_aicc.py` (or OSSFuzz if it is an OSSFuzz target)
```python
def test_my_new_target(self):
    local_backup = TEST_DIR / "aicc_testing/my_target/backup_abcdefg1234567_0"
    self.container, resource_dir, tmp_dir = setup_aicc_target(
        ...
    )
    run_and_validate_patcher(
        ...
    )
``` 

Congratulations, you have now added a new testcase!

## Features
Here are the features that can be turned on by setting specific environment variables. Each feature is independent and can be enabled or disabled individually.

Default Features:
MODEL=xxx, default is oai-gpt-4o

- Multi Poi