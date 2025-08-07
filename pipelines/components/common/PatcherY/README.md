# PatcherY
PatcherY is the next-generation [Patcherex](https://github.com/angr/patcherex), targeting source code and buildable
projects. 

## Installation
For now, please install using the development env:
```bash
pip install -e .[test]
```

### Verification 
Verify the installation by running pytest (must be on an X86 machine), this should take a max of 5 minutes:
```bash
pytest tests/test_core.py
```

This will require you to have `Git` installed and have a `OPENAI_API_KEY` environment variable set.
Everything should pass.

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
As an example, you can run just the Linux Kernel test with:
```bash
docker build -f tests/Dockerfile -t aixcc-patchery-tests .
pytest tests/test_aicc.py::TestPatcheryAICC::test_linux_tipc -s 
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

## AIxCC Pipeline Usage
For using this in the full pipeline, which is run with `pydatatask`, you can see the [patch.sh](/patch.sh) script file.
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

This results in a patch at the specified output path.

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




## Model Alias

In the configuration, model aliases are used to simplify referencing different models. Below are the aliases and their corresponding original models:
### OpenAI Models

| Alias	|Original Model |
|-------|--------------| 
| oai-gpt-3.5-turbo	| openai/gpt-3.5-turbo-0125 |
| oai-gpt-3.5-turbo-16k	| openai/gpt-3.5-turbo-16k |
| oai-gpt-4	| openai/gpt-4-0613 |
| oai-gpt-4-turbo	| openai/gpt-4-turbo-2024-04-09k |
| oai-gpt-4o | openai/gpt-4o-2024-05-13|

### Anthropic Models

| Alias	|Original Model |
|-------|--------------| 
| claude-3-opus	| claude-3-opus-20240229 |
| claude-3-sonnet | claude-3-sonnet-20240229 |
| claude-3.5-sonnet	| claude-3-5-sonnet-20240620 |
| claude-3-haiku	| claude-3-haiku-20240307 |

## Features
Here are the features that can be turned on by setting specific environment variables. Each feature is independent and can be enabled or disabled individually.

Default Features:
MODEL=xxx, default is oai-gpt-4o

Retrival_agumented_generation: Retrieve example from the codebase, otherwise on examples are used

Tree_of_thought: Three Expert Prompting Strategy

Optinal Features
RESET_IN_LOOP=1: restore the target codebase when any verification is failed, otherwise only restore the target codebase when the compilation fails

EXAMPLE=fixed: Disable RAG, use fixed example for few-shot learning; 

CHAIN_OF_THOUGHTS=1: use chain of thoughts strategy

EXPERTS=0: disable three experts prompts/Tree of Thoghts

COMPILE_ERROR_SUMMARY=1: summarize the compile error as feedback to patch generator

ENABLE_LLM_ANALYZER=1: enable an LLM-powered analyzer to analyze and summarize the report before it is fed to patch generators.

export OSS_FUZZ_TARGET=1; Skip functionality test for OSS_Fuzz Targets 


