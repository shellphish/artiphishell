#!/usr/bin/env bash

#https://github.com/shellphish-support-syndicate/targets-semis-libdwarf-57766/tree/2e1fccd45d7cb48e904a6633a73604897bbe868f
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TARGET=$1

pushd $SCRIPT_DIR
rm -rf ./ingested ./targets

ARVO_DIR=$SCRIPT_DIR/targets-semis-templates
if [ ! -d $ARVO_DIR ]; then
    git clone https://github.com/shellphish-support-syndicate/targets-semis-templates/
fi


ARVO_TARGET=$(realpath $(find $ARVO_DIR -type d -name "*$TARGET"))

echo "MODULE: $MODULE"

./rebuild_local.sh
./add_target.sh https://github.com/shellphish-support-syndicate/targets-semis-${TARGET}

PROJECT_YAML=$SCRIPT_DIR/targets/targets-semis-${TARGET}/project.yaml
cp -r ./targets/* $SCRIPT_DIR/../meta-components/aixcc-sc-capi/cp_root
INJECT_SCRIPT=$SCRIPT_DIR/arvo_inject_crash.sh
cat <<EOF > $INJECT_SCRIPT
#!/usr/bin/env bash

pushd $SCRIPT_DIR
while true;
do
    echo waiting....
    sleep 10
    HARNESS_INFO=\$(pd ls harness_splitter.target_harness_infos)
    if [ -z \$HARNESS_INFO ]; then
        echo "NO HARNESS INFO"
    else
        TARGET_DIR=\$(dirname \$0)/injected_metadata.yaml
        echo "harness_info_id: \"\$HARNESS_INFO\"" > \$TARGET_DIR
        echo "target_id: \"1\"" >> \$TARGET_DIR
        echo "cp_harness_id: \"id_1\"" >> \$TARGET_DIR
        echo "cp_harness_name: \"$(yq .harnesses.id_1.name $PROJECT_YAML)\"" >> \$TARGET_DIR
        echo "cp_harness_source_path: \"$(yq .harnesses.id_1.source $PROJECT_YAML)\"" >> \$TARGET_DIR
        echo "cp_harness_binary_path: \"$(yq .harnesses.id_1.binary $PROJECT_YAML)\"" >> \$TARGET_DIR
        echo "fuzzer: injected" >> \$TARGET_DIR
        pd inject povguy.crashing_input_path 1234 < $ARVO_TARGET/oss.poc
        pd inject povguy.crashing_input_metadata 1234 < \$TARGET_DIR
        echo "GOT HARNESS INFO"
        break
    fi
rm \$0
done
EOF
chmod +x $INJECT_SCRIPT
$INJECT_SCRIPT &
./run.sh
popd