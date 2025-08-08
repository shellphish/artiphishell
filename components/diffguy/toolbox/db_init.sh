#!/bin/bash

PROJECT_NAME=$1
SOURCE_REPO=$2
COMMIT_ID=$3
BACKUP_URL=$4
MODE=$5

# Validate required arguments
if [ -z "$PROJECT_NAME" ]; then
  echo "Error: PROJECT_NAME (argument 1) is required"
  exit 1
fi

if [ -z "$SOURCE_REPO" ]; then
  echo "Error: SOURCE_REPO (argument 2) is required"
  exit 1
fi

if [ -z "$COMMIT_ID" ]; then
  echo "Error: COMMIT_ID (argument 3) is required"
  exit 1
fi

if [ -z "$BACKUP_URL" ]; then
  echo "Error: BACKUP_URL (argument 4) is required"
  exit 1
fi

TARGET_DIR=~/diffguy_target/targets/$PROJECT_NAME
TARGET_BEFORE_DIR=$TARGET_DIR/before
TARGET_AFTER_DIR=$TARGET_DIR/after

SOURCE_DIR=~/diffguy_target/source/$PROJECT_NAME
SOURCE_BEFORE_DIR=$SOURCE_DIR/before
SOURCE_AFTER_DIR=$SOURCE_DIR/after
DATABASE_DIR=~/artiphishell/components/diffguy/dataset/db_codeql/$PROJECT_NAME

sudo rm -rf $TARGET_DIR
sudo rm -rf $SOURCE_DIR
sudo rm -rf $DATABASE_DIR
sudo rm -rf ~/artiphishell-ossfuzz-targets/

echo "[+]Creating directories..."

sudo git clone https://github.com/shellphish-support-syndicate/artiphishell-ossfuzz-targets.git
OSS_FUZZ_TARGET_PATH=~/artiphishell-ossfuzz-targets/projects/$PROJECT_NAME

mkdir -p  "$TARGET_BEFORE_DIR" "$TARGET_AFTER_DIR" "$SOURCE_BEFORE_DIR" "$SOURCE_AFTER_DIR"
sudo cp -r "$OSS_FUZZ_TARGET_PATH"/* "$TARGET_BEFORE_DIR"
sudo cp -r "$OSS_FUZZ_TARGET_PATH"/* "$TARGET_AFTER_DIR"
sudo git clone $SOURCE_REPO $SOURCE_BEFORE_DIR
sudo git clone $SOURCE_REPO $SOURCE_AFTER_DIR


cd $SOURCE_BEFORE_DIR
sudo git checkout main -f
sudo git checkout $COMMIT_ID -f

sudo chown -R root:root $SOURCE_BEFORE_DIR
sudo chown -R root:root $SOURCE_AFTER_DIR
sudo $(which oss-fuzz-build)  --architecture x86_64 --sanitizer address --instrumentation shellphish_codeql --project-source $SOURCE_BEFORE_DIR  $TARGET_BEFORE_DIR
sudo $(which oss-fuzz-build)  --architecture x86_64 --sanitizer address --instrumentation shellphish_codeql --project-source $SOURCE_AFTER_DIR  $TARGET_AFTER_DIR


mkdir -p $DATABASE_DIR
sudo cp "$TARGET_BEFORE_DIR/artifacts/work/sss-codeql-database.zip" "$DATABASE_DIR/database_before.zip"
sudo cp "$TARGET_AFTER_DIR/artifacts/work/sss-codeql-database.zip" "$DATABASE_DIR/database_after.zip"


if [ -z "$MODE" ]; then
  echo "NO Pulling"
  exit 1
fi

echo "Pulling code from  CI"
~/backup.sh $PROJECT_NAME $BACKUP_URL