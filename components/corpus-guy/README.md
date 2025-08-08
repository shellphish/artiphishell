# Corpus-Guy

- `run_inference_trace`: Guess candidate input file formats by tracing a sample of seeds for each format and comparing their coverage. Also runs `run_codeql_extract_dicts`.
- `run_inference_llm`: Guess candidate input file formats by using an LLM to analyze the project name, harness name, and harness source code. Also runs `run_codeql_extract_dicts`.
- `run_codeql_extract_dicts`: Uses CodeQL to create fuzzing dictionaries for the project.
- `run_kickstart`: Sync known crashes and permanence seeds to the fuzzers.