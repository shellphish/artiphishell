
#!/usr/bin/env bash

set -e
set -x

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <project_name>"
    exit 1
fi
PROJECT_GIT_URL="${1%.git}"
PROJECT_NAME=$(basename $PROJECT_GIT_URL)
FILENAME_DEFAULT="oss-fuzz-$PROJECT_NAME"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TARGET_DIR=$SCRIPT_DIR/targets
FILENAME=$TARGET_DIR/$FILENAME_DEFAULT
INGESTED_DIR=$SCRIPT_DIR/ingested
mkdir -p $INGESTED_DIR

DOCKER_IMAGE_NAME="artiphishell-targets/${FILENAME_DEFAULT}"

function target-docker-setup() {
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
        git clone $PROJECT_GIT_URL $FILENAME
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