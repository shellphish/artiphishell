# Grammar guy

## ALLOWIT!
Grammar guy uses coverage to create and refine grammars. These grammars can then be used to generate seeds that are tailored to hit desired functionality in the respective source code.

```
grammar-guy
├── docs/                               : Documentation
├── local_run/                          : Local test files
├── src/                                : Source code and scripts
│   └── grammar-guy/
|       ├── grammar-guy.py              : Main grammar-guy functionality
|       ├── config.py                   : Pipeline file handling, argument parsing etc.
|       ├── utils.py                    : Prints, file handling, grammar splitting, token limit checks etc.
├── target_building/                    : Files needed for docker build
├── test_features/                      : Pipeline tests
│   ├── test_feature_1/
│   ├── test_feature_2/
├── tools/                              : Installed tools for grammar-guy (so far only "generators")
├── .dockerignore
├── .gitignore
├── Dockerfile
├── pipeline.yaml
├── pyproject.toml
└── README.md
```

## Dependencies

- **coverage-guy**
- **coveragelib**
- **clang-indexer** 
- **fuzz-requestor**

## Running grammar-guy

### Locally

- Navigate to the [local.sh](./local_run/local.sh)
- Provide a backup for the target that should be tested (can be created by running pipeline and then [dumping the latest state](./local_run/dump-latest-state.sh))
- Provide a target for the **list of targets** (see below)

### Inside dev-container

- Start up the devcontainer by doing the following:
    - Press ``cmd + p``
    - Type ``> Rebuild`` --> ``Dev Containers: Rebuild and reopen in Dev Container`` and hit enter
- A new *code* instance should pop up, running a docker instance set up exactly as in the pipeline run (for details see [devcontainer.json](.decontainer/devcontainer.json))
- When inside, navigate to the [devcontainer-run-with-backup.sh](./local_run/devcontainer-run-with-backup.sh). 
    - Run by providing: 
        - ``fuzzer``*(=input generator)* (*nautilus* or *grammarinator*)
        - ``target`` *name* from the list of targets below 
        - ``target_backup`` (usually like above *name* + *_backup*)

### Local pipeline run

- To run the grammar-guy as part of a local pipeline, execute the [run.sh](./test_features/run.sh) and a target from the **list of targets**
- Currently must change ``OPENAI_API_KEY`` because ``LITELLM`` is not up. If ``LITELLM`` is up, can just uncomment the two lines above and comment out ``OPENAI_API_KEY`` line

#### Backups

- Backups are created from the pipeline runs only or supplied from a full pipeline run an mounted into the devcontainer. 
- To create a backup, run the pipeline and afterwards (after success), run [dump-latest-state.sh](./test_features/dump-latest-state.sh)
- This will create a folder called **backup**. Rename this folder to ``<target>_backup``

### List of Targets (to be extended)

- ``nginx``
- ``oniguruma-1``

### Visualizing grammar runs

```shell
# Start grammar_guy; take note of EVENTS_DIR in the log
HARNESS_INFO_ID=<harness_id> ./run-gg-from-backup.sh /aixcc-backups/<backup_dir>

# Start the webview; this updates live in case you're already running grammar-guy
python3 ./src/scripts/run_webview.py <events_dir>
```
