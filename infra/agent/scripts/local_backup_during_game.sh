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

if [[ "$AZURE_STORAGE_ACCOUNT_NAME" == *ci* ]]; then
  if [ "$ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP" != "true" ]; then
    echo "Skipping local backup as we are in the CI environment"
    exit 0
  fi
fi

set -ex
SCRIPT_DIR=$(realpath $(dirname $0))
ROOT_DIR=$(realpath $SCRIPT_DIR/../../..)

cd $ROOT_DIR

if [ -f /tmp/.backup_in_progress ]; then
  echo "Backup already in progress"
  exit 0
fi

touch $1

export TEMP=/backup/

trap "rm -f /tmp/.backup_in_progress" EXIT
touch /tmp/.backup_in_progress
rm -f /tmp/.backup_complete || true

timestamp=$(date +%s)

mkdir -p /backup/pipeline/

BACKUP_DIR="/backup/pipeline/backup-$CRS_TASK_NUM-${timestamp}"


set +e

# Arg1 = path to tar file

mkdir -p /backup


mkdir -p $BACKUP_DIR

echo "=== Backing pipeline ==="
#time pd backup --all $BACKUP_DIR
time /app/infra/agent/scripts/smart_pd_backup.py --skip-artifacts $BACKUP_DIR

echo "=== Collecting Metadata ==="

echo "=== Collecting Pipeline Status ==="

(
  pd status > $BACKUP_DIR/pd_status.txt || true
  pd status -j > $BACKUP_DIR/pd_status.json || true
) &

df -h > $BACKUP_DIR/df.txt || true

mkdir -p $BACKUP_DIR/why_ready || true

cp -r /tmp/pydatatask-emergency $BACKUP_DIR/pydatatask-emergency || true

cp /pdt/pod_ips.txt $BACKUP_DIR/pod_ips.txt || true
cp /pdt/dns_lookups.txt $BACKUP_DIR/dns_lookups.txt || true


#(
## For every task in pd status we will run why ready
#TASKS=$(pd status -j | jq -cr 'keys[]')
#for TASK in $TASKS; do
#  (pd why-ready $TASK > $BACKUP_DIR/why_ready/$TASK || true) &
#  sleep 5
#done
#) &


echo "=== Backing up k8s metadata ==="

#(
(kubectl get pods -o wide > $BACKUP_DIR/k8s_pods.txt || true) &
#(kubectl describe pods > $BACKUP_DIR/k8s_describe_pods.txt || true)
#(kubectl describe nodes > $BACKUP_DIR/k8s_describe_nodes.txt || true)
#(kubectl get services -o wide > $BACKUP_DIR/k8s_services.txt || true)
#(kubectl get events --all-namespaces > $BACKUP_DIR/k8s_events.txt || true)
#) &

echo "=== Backing up running tasks ==="
mkdir -p $BACKUP_DIR/long-running

(
# Get all pods with CRS label
for POD in $(kubectl get pods -o jsonpath='{.items[*].metadata.name}')
do
  if [[ ! $POD =~ ^artiphishell ]]; then
    continue
  fi
  if [ ! -z "$CRS_TASK_NUM" ]; then
    if [[ ! $POD =~ ^artiphishell-$CRS_TASK_NUM ]]; then
      continue
    fi
  fi

  # For some pods, we have too many to backup in time
  # So we randomly decide to save 1/10 of them
  RANDOM_SAMPLE=false
  if [[ "$(echo "$POD" | egrep 'aflpp-fuzz-[^m]')" ]]; then
    RANDOM_SAMPLE=true
  fi

  if [[ "$(echo "$POD" | egrep 'jazzer-fuzz-[^my]{3}')" ]]; then
    RANDOM_SAMPLE=true
  fi

  # Keep 1/30 of all replica pods
  if [[ "$RANDOM_SAMPLE" == "true" ]]; then
    if [[ $((RANDOM % 30)) -ne 0 ]]; then
      echo "Skipping $POD because it is a replica pod"
      continue
    fi
  fi

  # Extract task, job, replicant from pod name
  if [[ $POD =~ -set- ]]; then
    read TASK JOB <<< $(echo $POD | awk -F'-' '{print substr($0, 1, length($0)-length($NF)-1), $NF}')
    REPLICANT="0"
  else
    read TASK JOB REPLICANT <<< $(echo $POD | awk -F'-' '{print substr($0, 1, length($0)-length($NF)-length($(NF-1))-2), $(NF-1), $NF}')
  fi

  # Trim artiphishell- prefix from task name
  if [ ! -z "$CRS_TASK_NUM" ]; then
    TASK=${TASK#artiphishell-$CRS_TASK_NUM-}
    TASK=${TASK#artiphishell-$CRS_TASK_NUM-set-}
  fi
  TASK=${TASK#artiphishell-set-}
  TASK=${TASK#artiphishell-}
  # replace - with _
  TASK=${TASK//-/_}

  echo "task=$TASK job=$JOB replicant=$REPLICANT"
  
  # Create log directories
  mkdir -p $BACKUP_DIR/$TASK.logs
  mkdir -p $BACKUP_DIR/long-running
  
  # Get pod logs
  kubectl logs $POD --tail 50000 > $BACKUP_DIR/$TASK.logs/$REPLICANT-$JOB || true
  
  # Record replicant-job
  echo "$REPLICANT-$JOB" >> $BACKUP_DIR/long-running/$TASK
done
) &

# SEARCH: Service Backup

# TODO fix this

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
backup_service litellm litellm
) &

API_POD=$(kubectl get pod -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}')
kubectl cp $API_POD:/shared/llm_budget_manager.log $BACKUP_DIR/llm_budget_manager.log || true
kubectl cp $API_POD:/shared/llm_budget_manager_state.json $BACKUP_DIR/llm_budget_manager.log || true
kubectl cp $API_POD:/shared/shared/llm_budget_bonus.json $BACKUP_DIR/llm_budget_manager.log || true
kubectl cp $API_POD:/shared/shared/task_pool_state.json $BACKUP_DIR/llm_budget_manager.log || true


(
  mkdir -p $BACKUP_DIR/permanence_server.logs
  PERMANENCE_SERVER_POD=$(kubectl get pod -l app.kubernetes.io/name=permanence -o jsonpath='{.items[0].metadata.name}')
  kubectl logs $PERMANENCE_SERVER_POD > $BACKUP_DIR/permanence_server.logs/1 || true
  echo "1" >> $BACKUP_DIR/long-running/permanence_server

  rm -rf /tmp/permanence
  mkdir /tmp/permanence
  PERMANENCE_SERVER_POD=$(kubectl get pod -l app.kubernetes.io/name=permanence -o jsonpath='{.items[0].metadata.name}')
  kubectl cp $PERMANENCE_SERVER_POD:/data /tmp/permanence/ --retries 5 2>/dev/null
  pushd /tmp/
  tar cfz $BACKUP_DIR/permanence.tar.gz permanence --checkpoint=1000
  popd
) &

function daemonset_logs() {
  DAEMONSET_NAME=$1
  NAMESPACE=default
  LABELS="app.kubernetes.io/name=$DAEMONSET_NAME"
  PODS=$(kubectl get pods -n $NAMESPACE -l $LABELS -o jsonpath='{.items[*].metadata.name}')

  # If no pods found, try with just name
  if [ -z "$PODS" ]; then
    LABELS="name=$DAEMONSET_NAME"
    PODS=$(kubectl get pods -n $NAMESPACE -l $LABELS -o jsonpath='{.items[*].metadata.name}')
  fi

  NAME_NO_DASHES=${DAEMONSET_NAME//-/_}

  mkdir -p $BACKUP_DIR/$NAME_NO_DASHES.logs

  for POD in $PODS; do
    kubectl logs $POD > $BACKUP_DIR/$NAME_NO_DASHES.logs/$POD || true
    echo "$POD" >> $BACKUP_DIR/long-running/$NAME_NO_DASHES
  done
}

(daemonset_logs docker-builder || true) &
(daemonset_logs host-config || true) &
(daemonset_logs otel-collector || true) &
(daemonset_logs image-puller || true) &

BACKUP_TAR=/backup/backup-${CRS_TASK_NUM}-${timestamp}.tar.gz

cp /pdt/agent.log $BACKUP_DIR/agent.log || echo "No agent.log"
cp /pdt/agent-http.log $BACKUP_DIR/agent-http.log || echo "No agent-http.log"
cp /pdt/monitor_by_project.log $BACKUP_DIR/monitor_by_project.log || echo "No monitor_by_project.log"
cp /pdt/update_project_status.log $BACKUP_DIR/update_project_status.log || echo "No update_project_status.log"
cp -r /pdt/profiling_data/ $BACKUP_DIR/profiling_data/ || echo "No profiling_data"

chmod 777 -R $BACKUP_DIR

mkdir $BACKUP_DIR/crs_scratch
SUBMITTER_POD=$(kubectl get pod -l task=submitter -o jsonpath='{.items[0].metadata.name}')

kubectl cp $SUBMITTER_POD:/crs_scratch $BACKUP_DIR/crs_scratch/ --retries 5
pushd $BACKUP_DIR
tar cfz crs_scratch.tar.gz crs_scratch
rm -rf crs_scratch
popd

pushd $BACKUP_DIR

# Some artifacts are way too large!
function remove_artifacts() {
  # Iterate over all files and replace them with a text file that says "artifact too large"
  local ARTIFACTS_DIR=$1
  for FILE in $(find $ARTIFACTS_DIR -type f); do
    FILE=$(realpath $FILE)
    echo "Artifact excluded from backup due to size of $(du -sh $FILE | cut -f1)" > $FILE
  done
}

wait

#remove_artifacts $BACKUP_DIR/oss_fuzz_project_build.project_build_artifacts
#remove_artifacts $BACKUP_DIR/oss_fuzz_project_build.project_run_artifacts
#remove_artifacts $BACKUP_DIR/oss_fuzz_project_run.project_run_artifacts
#remove_artifacts $BACKUP_DIR/oss_fuzz_project_run.project_volumes_id

popd

echo "=== Backing up analysisgraph ==="

rm -rf /tmp/analysisgraph
mkdir /tmp/analysisgraph
ANALYSIS_GRAPH_POD=$(kubectl get pod -l app.kubernetes.io/name=analysisgraph-${CRS_TASK_NUM} -o jsonpath='{.items[0].metadata.name}')

# ⬇️ Replaces kubectl cp and follows symlinks
time kubectl exec "$ANALYSIS_GRAPH_POD" -- \
    tar --dereference -C / -cf - var/lib/neo4j | tar -C /tmp/analysisgraph -xf -

pushd /tmp/
time tar cfz $BACKUP_DIR/analysisgraph.tar.gz analysisgraph --checkpoint=1000
popd



if [ -f /app/infra/agent/scripts/get_llm_usage.sh ]; then
  time /app/infra/agent/scripts/get_llm_usage.sh $BACKUP_DIR/llm_usage.json || echo "No llm_usage.json"
fi

cp /tmp/backup.log $BACKUP_DIR/backup.log || echo "No backup.log"

if [ ! -z "$AZURE_STORAGE_CONTAINER_NAME" ]; then
  if [ "$AZURE_STORAGE_ACCOUNT_NAME" == "artiphishellci" ] && [ "$ARTIPHISHELL_GLOBAL_ENV_ENABLE_IN_RUN_BACKUP" != "true" ]; then
    echo "⚠️ Refusing to upload backup outside of the game cluster"
  else
    DO_TAR=true
  fi
fi

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

touch /tmp/.backup_complete




