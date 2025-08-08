
#!/usr/bin/env bash

set -e
set -x

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <project_name>"
    exit 1
fi
PROJECT_NAME=$1
FILENAME_DEFAULT="oss-fuzz-$1"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TARGET_DIR=$SCRIPT_DIR/targets
FILENAME=$TARGET_DIR/$FILENAME_DEFAULT
INGESTED_DIR=$SCRIPT_DIR/ingested
mkdir -p $INGESTED_DIR

DOCKER_IMAGE_NAME="artiphishell-targets/${FILENAME_DEFAULT}"
OSS_FUZZ_DIR=$TARGET_DIR/.oss-fuzz

if [ ! -d "$OSS_FUZZ_DIR" ]; then
    git clone https://github.com/google/oss-fuzz.git $OSS_FUZZ_DIR
fi

function target-docker-setup() {
    docker pull gcr.io/oss-fuzz-base/base-runner
    docker pull gcr.io/oss-fuzz-base/base-builder
    docker pull gcr.io/oss-fuzz-base/base-builder-jvm
    docker pull gcr.io/oss-fuzz-base/base-builder-python
    docker build -t $DOCKER_IMAGE_NAME "$FILENAME" \
        --secret id=GITHUB_CRED_URL,src=$HOME/.git-credentials

    id=$(docker create "$DOCKER_IMAGE_NAME")
    docker cp $id:/src/ $FILENAME/src/
    docker cp $id:/work/ $FILENAME/work/
    docker cp $id:/out/ $FILENAME/out/
    docker rm -v $id

    # add/overwrite the "docker_image" key to the project.yaml file
    DOCKER_IMAGE_NAME="$DOCKER_IMAGE_NAME" yq eval -i '.shellphish_docker_image = env(DOCKER_IMAGE_NAME)' "$FILENAME/project.yaml"
    PROJECT_NAME="$PROJECT_NAME" yq eval -i '.shellphish_project_name = env(PROJECT_NAME)' "$FILENAME/project.yaml"
}

mkdir -p $TARGET_DIR
rm -rf $FILENAME

while true;
do

    if [ -d "$FILENAME" ]; then
        echo "Directory $FILENAME already exists."
        pushd "$FILENAME" || exit 1
        # TODO check if the gitrepo or any soruce was updated...
        target-docker-setup
        touch .ready
        popd
    else
        cp -r "$OSS_FUZZ_DIR/projects/$PROJECT_NAME" "$FILENAME"
        (
            pushd "$FILENAME" || exit 1
            target-docker-setup
            touch .ready
            popd
        )
    fi

    OUTPUT=$INGESTED_DIR/$FILENAME_DEFAULT.tar.gz
    (cd $FILENAME && tar --owner=0 --group=0 -czf "$OUTPUT" .)
    tar tf $OUTPUT 1>/dev/null
    if [ $? -eq 0 ]; then
        break
    fi
done

docker pull gcr.io/oss-fuzz-base/base-runner:latest