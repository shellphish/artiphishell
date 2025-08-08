# Debug Lib


This library allows any component to interact with a debugger. At the moment we only support GDB, but hopefully soon we will have support for other debuggers as well.

## Usage:
To use debug_lib, your task must import the `target_built_for_debugging` (targets built with debugging instrumentation, one of the outputs of `dyva_build`), and the `target_harness_info` repo. For example:

``` yaml
repo_classes:
    targets_built_for_debugging: FilesystemRepository
    target_metadatas: MetadataRepository
tasks:
    your_task:
        target_built_for_debugging:
            repo: targets_built_for_debugging
            kind: InputFilepath
            key: <target_id>
        target_harness_info:
            repo: target_harness_infos
            kind: InputFilepath
            key: <target_id>
        
        template: |
            export TARGET_HARNESS_INFO_PATH={{ target_harness_info | shquote }}
            export TARGET_BUILT_FOR_DEBUGGING={{ target_built_for_debugging | shquote }}

            mkdir -p /shared/yourcomponent/
            TMPDIR=$(mktemp -d -p /shared/yourcomponent/)
            cp -ra $TARGET_BUILT_FOR_DEBUGGING $TMPDIR/cp-folder
            export TARGET_DIR=$TMPDIR/cp-folder/
```

Then, in your component, to use debug_lib you must import the `debug_lib`


``` python
from debug_lib.debuggers import get_debugger, start_remote_debugger, get_info_at_location

with open(TARGET_HARNESS_INFO_PATH, "r") as f:
        harness_info = yaml.safe_load(f)

remote = TARGET_DIR / "src" / "gdb.socket"
# Initiating remote debugger
binary_path = os.path.join(TARGET_DIR, harness_info["cp_harness_binary_path"])
start_remote_debugger(TARGET_DIR, Path(harness_info["cp_harness_binary_path"]), harness_info["cp_harness_name"])


# You can either use existing functions like get_info_at_location
context_dict, context_str = get_info_at_location(binary_path, input_file, remote: str, src_file_name: str, line_number: int, target_dir)
# Here context dict consists of Backtrace, local variable info, and registers info at the given src_file_name, line_number location

# Or you can just play with 🔥 and provide raw gdb commands
debugger = get_debugger(binary_path, input_file, remote)
out = debugger.raw('your instruction')
context = debugger.context

```
