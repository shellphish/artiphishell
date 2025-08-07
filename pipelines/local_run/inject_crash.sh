#!/bin/bash

# set -x

if [ -z "$SHOULD_INJECT" ]; then
    echo "SHOULD_INJECT is not set. Exiting"
    exit 1
fi

if [ -z "$TARGET_DIR_NAME" ]; then
    echo "TARGET_DIR_NAME is not set for injection. Exiting"
    exit 1
fi

echo "Injecting crash for $TARGET_DIR_NAME"

cat << EOF > ./injector.sh
#!/usr/bin/env bash
set -x
while true;
do
    echo Waiting for harness info: $TARGET_DIR_NAME
    HARNESS_INFO=\$(pd ls harness_splitter.target_harness_infos 2>&1)
    PROJECT_YAML=\$(realpath \$(find ./local_run/targets -type f -name "project.yaml"))
    
    sleep 10

    if [ -z \$HARNESS_INFO ]; then
        echo "NO HARNESS INFO"
    else
        echo "GOT HARNESS INFO"
        TARGET_METADATA=\$(dirname \$0)/injected_metadata.yaml
        echo "harness_info_id: \$HARNESS_INFO" > \$TARGET_METADATA
        echo "target_id: 1" >> \$TARGET_METADATA
        echo "cp_harness_id: id_1" >> \$TARGET_METADATA
        echo "cp_harness_name: \$(yq .harnesses.id_1.name \$PROJECT_YAML)" >> \$TARGET_METADATA
        echo "cp_harness_source_path: \$(yq .harnesses.id_1.source \$PROJECT_YAML)" >> \$TARGET_METADATA
        echo "cp_harness_binary_path: \$(yq .harnesses.id_1.binary \$PROJECT_YAML)" >> \$TARGET_METADATA
        echo "fuzzer: injected" >> \$TARGET_METADATA
        
        echo "Checking ./local_run/injectables/\$TARGET_DIR_NAME/oss.poc"

        if [ ! -f ./local_run/injectables/\$TARGET_DIR_NAME/oss.poc ]; then
            echo "oss.poc not found. Exiting"
            break
        fi
           
        pd inject povguy.crashing_input_path 1234 < \./local_run/injectables/\$TARGET_DIR_NAME/oss.poc
        pd inject povguy.crashing_input_metadata 1234 < \$TARGET_METADATA
        pd inject povguy.crashing_input_metadata_path 1234 < \$TARGET_METADATA
        pd inject povguy.crashing_input_id 1234 < \$TARGET_METADATA
        echo "CRASH_INJECTION_SUCCESS=yes" >> "$GITHUB_ENV"
        break
    fi
done
rm \$0
EOF
chmod +x ./injector.sh

./injector.sh
