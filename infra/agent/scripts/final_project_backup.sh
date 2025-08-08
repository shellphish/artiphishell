#!/bin/bash
umask 022

date

echo
echo
echo "================ STARTING BACKUP ================"
echo
echo

# This script simply creates a backup of the CRS into a local directory
# It only uploads to the Azure Storage within the round subscription
# So that artifacts can be retrived when the subscription is returned
# to the team after the round is over and access is restored

if [ "$AZURE_STORAGE_ACCOUNT_NAME" == "artiphishellci" ]; then
  if [ "$ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP" != "true" ]; then
    echo "Skipping local backup as we are in the CI environment"
    exit 0
  fi
fi

set -ex
SCRIPT_DIR=$(realpath $(dirname $0))
ROOT_DIR=$(realpath $SCRIPT_DIR/../../..)

if [ -f /tmp/.backup_in_progress_tiny ]; then
  echo "Backup already in progress"
  exit 0
fi

touch $1

export TEMP=/backup/

trap "rm -f /tmp/.backup_in_progress_tiny" EXIT
touch /tmp/.backup_in_progress_tiny
rm -f /tmp/.backup_complete_tiny || true

timestamp=$(date +%s)

mkdir -p /backup/pipeline/

BACKUP_DIR="/backup/pipeline/backup-tiny-$CRS_TASK_NUM-${timestamp}"


set +e

mkdir -p /backup

mkdir -p $BACKUP_DIR

echo "=== Backing pipeline ==="
time /app/infra/agent/scripts/tiny_pd_backup.py $BACKUP_DIR

echo "=== Collecting Metadata ==="

echo "=== Collecting Pipeline Status ==="

(
  pd status -j > $BACKUP_DIR/pd_status.json || true
) &

echo "=== Backing up k8s metadata ==="

(
(kubectl get pods -o wide > $BACKUP_DIR/k8s_pods.txt || true)
) &

function backup_service() {
  local name=$1
  local name_under=$2
  local task_num=${3:-1}

  mkdir -p $BACKUP_DIR/$name_under.logs
  AGENT_POD=$(kubectl get pod -l app.kubernetes.io/name=$name -o jsonpath='{.items[0].metadata.name}')
  
  # Get current logs
  time kubectl logs $AGENT_POD > $BACKUP_DIR/$name_under.logs/$task_num || true

  # Get number of restarts for this pod
  RESTARTS=$(kubectl get pod $AGENT_POD -o jsonpath='{.status.containerStatuses[0].restartCount}')
  
  # If pod has restarted, also get previous logs
  if [ "$RESTARTS" -gt 0 ]; then
    time kubectl logs $AGENT_POD --previous > $BACKUP_DIR/$name_under.logs/$task_num.previous || true
  fi
  
  echo "$task_num" >> /tmp/ci/long-running/$name_under
}

(
backup_service pydatatask-agent-${CRS_TASK_NUM} pydatatask_agent ${CRS_TASK_NUM}
backup_service api crs_api
backup_service codeql-${CRS_TASK_NUM} codeql_server ${CRS_TASK_NUM}
backup_service functionresolver-${CRS_TASK_NUM} functionresolver_server ${CRS_TASK_NUM}
backup_service analysisgraph-${CRS_TASK_NUM} analysis_graph ${CRS_TASK_NUM}
) &

BACKUP_TAR=/backup/backup-tiny-${CRS_TASK_NUM}-${timestamp}.tar.gz
cp /pdt/agent.log $BACKUP_DIR/agent.log || echo "No agent.log"
cp /pdt/agent-http.log $BACKUP_DIR/agent-http.log || echo "No agent-http.log"
cp /pdt/monitor_by_project.log $BACKUP_DIR/monitor_by_project.log || echo "No monitor_by_project.log"
cp /pdt/update_project_status.log $BACKUP_DIR/update_project_status.log || echo "No update_project_status.log"
cp -r /pdt/profiling_data/ $BACKUP_DIR/profiling_data/ || echo "No profiling_data"

chmod 777 -R $BACKUP_DIR

if [ -f /app/infra/agent/scripts/get_llm_usage.sh ]; then
  time /app/infra/agent/scripts/get_llm_usage.sh $BACKUP_DIR/llm_usage.json || echo "No llm_usage.json"
fi

if [ ! -z "$AZURE_STORAGE_CONTAINER_NAME" ]; then
  if [ "$AZURE_STORAGE_ACCOUNT_NAME" == "artiphishellci" ] && [ "$ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP" != "true" ]; then
    echo "⚠️ Refusing to upload backup outside of the game cluster"
  else
    DO_TAR=true
  fi
fi

wait

if [ "$DO_TAR" == "true" ]; then
  date
  pushd $(dirname $BACKUP_DIR)
  (
    set -e
    time tar cfz $BACKUP_TAR ./$(basename $BACKUP_DIR) --checkpoint=1000 && rm -rf $BACKUP_DIR
    set +e
  )
  popd
fi
wait

if [ ! -z "$AZURE_STORAGE_CONTAINER_NAME" ]; then
  if [ "$AZURE_STORAGE_ACCOUNT_NAME" == "artiphishellci" ] && [ "$ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP" != "true" ]; then
    echo "⚠️  Refusing to upload backup outside of the game cluster"
  else
    TAR_NAME=$(basename $BACKUP_TAR)
    echo "☁️🗃️  Uploading backup to Azure Storage"
    time az storage blob upload \
      --container-name $AZURE_STORAGE_CONTAINER_NAME \
      --account-name $AZURE_STORAGE_ACCOUNT_NAME \
      --file $BACKUP_TAR \
      --name "backups/$DEPLOYMENT_NAME/pipeline-backup/$TAR_NAME" \
      --sas-token "$AZURE_STORAGE_STS_TOKEN" \
      --connection-string "$AZURE_STORAGE_CONNECTION_STRING" \
       || true
  fi

  # Since we have the TAR we will not need the directory anymore
  rm -rf $BACKUP_DIR || true

fi

echo "Backup complete"

touch /tmp/.backup_complete_tiny