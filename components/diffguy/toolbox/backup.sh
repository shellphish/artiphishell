#/bin/bash
PROJECT=$1
BACKUP_URL=$2
# Validate required arguments
if [ -z "$PROJECT" ]; then
  echo "Error: PROJECT_NAME (argument 1) is required"
  exit 1
fi

if [ -z "$BACKUP_URL" ]; then
  echo "Error: BACKUP_URL (argument 2) is required"
  exit 1
fi


BACKUP_DIR=/home/$USER/aixcc-backups/backup-$PROJECT
BACKUP=/home/$USER/aixcc-backups/backup-$PROJECT.tar.gz
T=/home/$USER/artiphishell/components/diffguy/dataset/corpus
TP_DIR=$T/$PROJECT/
mkdir -p $TP_DIR
TARGET_JSON=$TP_DIR/functions_index
TARGET_DIR=$TP_DIR/functions_jsons_dir
wget $BACKUP_URL -O $BACKUP
cd /home/$USER/aixcc-backups/
unar $BACKUP
mv $BACKUP_DIR-* $BACKUP_DIR
sudo chown -R $USER:$USER $BACKUP_DIR

sudo cp $BACKUP_DIR/generate_full_function_index.target_functions_index/* $TARGET_JSON
sudo unar $BACKUP_DIR/generate_full_function_index.target_functions_jsons_dir/* -D -o $TARGET_DIR
