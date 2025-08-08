#!/bin/bash

set -e
set -x

REPO_URL="https://github.com/apache/tika.git"

# commits mapping
declare -A commits
commits[1]="116edb30dc5fd26770216ccffcf873f4952a5c2a" # latest commit on master 10/5/2024
commits[2]="1dbf284b7131b13f0ab35162ac5914e2aba7baa6" # release from April  2.9.2-rc2
commits[3]="3b4365064ea9354c4dd0a2fc0b6f5348f1ae43e1" # release 2.9.1-rc1
commits[4]="ce99af801ad476b96aee78c8046d12de2a00cfa6" # release 2.9.0-rc1

# Usage information
usage() {
    echo "Usage: $0 [-n <1|2|3|4>] [-c <commit_hash>] [-j <threads>] [-p <project>]"
    echo " -n <number> : Specify a predefined commit number (1, 2, 3, or 4)"
    echo " -c <commit_hash> : Alternatively, specify a commit hash directly"
    echo " -j <threads> : Specify the number of threads to use for parallel builds"
    echo " -p <project> : (Optional) Specify a specific subproject to build (e.g., tika-server-standard)"
    exit 1
}

threads=1
project=""
while getopts "n:c:j:p:" opt; do
    case ${opt} in
        n)
            number=$OPTARG
            ;;
        c)
            commit=$OPTARG
            ;;
        j)
            threads=$OPTARG
            ;;
        p)
            project=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done

# If both options are provided or none are provided, show usage
if [[ -z "$number" && -z "$commit" ]]; then
    echo "You must specify either a commit number or a commit hash."
    usage
fi

if [[ -n "$number" && -n "$commit" ]]; then
    echo "You can't specify both a commit number and a commit hash at the same time."
    usage
fi

# Check if the provided number is valid and map to the corresponding commit hash
if [[ -n "$number" ]]; then
    if [[ -z "${commits[$number]}" ]]; then
        echo "Invalid number provided. Please choose 1, 2, 3, or 4."
        usage
    fi
    commit=${commits[$number]}
fi

mkdir -p /tmp/build_harness/
pushd /tmp/build_harness

if [ ! -d "tika" ]; then
    git clone "$REPO_URL"
fi

cd tika

git fetch origin
git checkout "$commit"


if [[ -n "$project" ]]; then
    # If the user specifies a project, build only that part of the project
    mvn clean install -T"$threads" -am -pl :"$project" -Dossindex.skip -Dmaven.repo.local=../target_build
else
    # If no project is specified, build the entire project
    mvn clean install -T"$threads" -Dmaven.repo.local=../target_build
    # -Dossindex.skip: to disable ossindex check
fi


echo "Build completed for commit: $commit"
popd
pwd
cp build.gradle.updated /tmp/build_harness/

pushd /tmp/build_harness/

FUZZ_TARGET_DIR="/tmp/build_harness/tika-fuzz"

# Check if the tika-fuzz directory exists
if [ ! -d "$FUZZ_TARGET_DIR" ]; then
  echo "Directory $FUZZ_TARGET_DIR does not exist. Cloning the repository and setting up build.gradle."
  git clone https://github.com/centic9/tika-fuzz.git
  cp build.gradle.updated "$FUZZ_TARGET_DIR/build.gradle"
else
  echo "Directory $FUZZ_TARGET_DIR already exists. Skipping clone and build.gradle copy."
fi

# Navigate to the tika-fuzz directory and build using Gradle
cd "$FUZZ_TARGET_DIR"
./gradlew shadowJar

# To directly use fuzzing from here uncomment this line and update path to jazzer. This should be run from /tmp/build_harness/tika-fuzz

# ./jazzer --cp=build/libs/build_harnes-all.jar --instrumentation_excludes=org.apache.logging.**:org.slf4j.**:com.microsoft.schemas.**:org.openxmlformats.schemas.**:org.apache.xmlbeans.**:com.google.protobuf.**:com.google.common.**:ucar.nc2.**:org.mozilla.universalchardet.**:org.jdom2.**:javax.activation.**:javax.xml.bind.**:com.sun.** --target_class=org.dstadler.tika.fuzz.Fuzz -rss_limit_mb=8192

