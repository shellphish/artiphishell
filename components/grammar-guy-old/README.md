# The Grammar GUY aka. Spearfuzz

## Running the thing

- Now integrated with the pipeline and dockerized.
- run `docker_run.sh`
- use `test` to run the grammar-guy using the standard parameters

## Docker folder structure

```plaintext
shellphish
├── coverage
├── generated-inputs
    ├── generators      (grammarinator generators)
├── grammars
├── scripts
└── src
    ├── prompts         (prompts for agentlib)
    ├── volumes         (stuff from agentlib)
    ├── allowlist.txt   (allowed functions for coverage)
    └── grammar-guy.py  (main program)
```