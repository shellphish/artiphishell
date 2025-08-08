#!/bin/bash
umask 022

set -ex
SCRIPT_DIR=$(realpath $(dirname $0)/..)
ROOT_DIR=$(realpath $SCRIPT_DIR/../../..)

cd $ROOT_DIR

export INFLUXDB_URL="http://telemetrydb:${TELEMETRYDB_SERVICE_PORT:-8086}"

if [ -z "$GITHUB_STEP_SUMMARY" ]; then
  export GITHUB_STEP_SUMMARY=/tmp/summary.md
fi
if [ -z "$GITHUB_ENV" ]; then
  export GITHUB_ENV=/tmp/github_env
fi

if [ -z "$GITHUB_WORKSPACE" ]; then
  export GITHUB_WORKSPACE=/tmp/
fi

mkdir -p $HOME/.ssh

touch /tmp/.backup_in_progress
rm -f /tmp/.backup_complete || true

trap "rm -f /tmp/.backup_in_progress" EXIT

set +e

set +x
if [ ! -f $HOME/.ssh/id_rsa ]
then
  if [ -z "$BACKUP_SSH_KEY" ]; then
    echo "BACKUP_SSH_KEY is not set"
    exit 1
  fi
    echo "$BACKUP_SSH_KEY" | base64 -d | sed 's/^[[:space:]]*//' > $HOME/.ssh/id_rsa
fi
chmod 600 $HOME/.ssh/id_rsa
cp $HOME/.ssh/id_rsa $GITHUB_WORKSPACE/ci_ssh

sha256sum $GITHUB_WORKSPACE/ci_ssh

if [ ! -f $GITHUB_WORKSPACE/ci_ssh ]
then
    cp $HOME/.ssh/id_rsa $GITHUB_WORKSPACE/ci_ssh
fi
chmod 600 $GITHUB_WORKSPACE/ci_ssh
set -x

date

export REAL_TARGET_NAME=$TARGET_NAME
if [ "$TARGET_NAME" == "multi" ]; then
  ALL_TASKS=$(pd ls pipeline_input.crs_task)
  # If there is only one task, we can set the TARGET_NAME to the task name
  if [ $(echo "$ALL_TASKS" | wc -l) -eq 1 ]; then
    # Read the targer from the task yaml .project_name
    export REAL_TARGET_NAME=$(pd cat pipeline_input.crs_task $(echo "$ALL_TASKS" | head -n 1) | yq -r '.project_name')
  fi
fi

# Arg1 = path to tar file

tmpdir=$(mktemp -d)

export BACKUP_DIR=$tmpdir/backup-${TARGET_NAME}-${RUN_ID}
mkdir -p $BACKUP_DIR

echo "=== Backing pipeline ==="
#pd backup --all $BACKUP_DIR
time /app/infra/agent/scripts/smart_pd_backup.py $BACKUP_DIR

date

echo "=== Collecting Metadata ==="
(
  pd graph --out-dir $BACKUP_DIR || true
) || true &

echo "=== Collecting Pipeline Status ==="

(
  pd status > $BACKUP_DIR/pd_status.txt || true
) || true &

mkdir -p $BACKUP_DIR/why_ready || true
# For every task in pd status we will run why ready
(
  TASKS=$(pd status -j | jq -cr 'keys[]')
  for TASK in $TASKS; do
    (pd why-ready $TASK > $BACKUP_DIR/why_ready/$TASK || true) &
  done
) || true &

date

echo "=== Backing up k8s metadata ==="

time kubectl get pods -o wide > $BACKUP_DIR/k8s_pods.txt || true
time kubectl describe pods > $BACKUP_DIR/k8s_describe_pods.txt || true
time kubectl describe nodes > $BACKUP_DIR/k8s_describe_nodes.txt || true
time kubectl get services -o wide > $BACKUP_DIR/k8s_services.txt || true
time kubectl get events --all-namespaces > $BACKUP_DIR/k8s_events.txt || true

tar cf $BACKUP_DIR/all_k8s_metadata.tar.gz /backup/k8s_info/all_k8s_metadata_${CRS_TASK_NUM}.tar.gz || true
cat /backup/k8s_info/*/k8s_events.txt >> $BACKUP_DIR/k8s_events_$CRS_TASK_NUM.txt || true

function collect_disk_io_usage() {
  NAMESPACE=default
  LABELS="app=iotop-monitor"
  PODS=$(kubectl get pods -n $NAMESPACE -l $LABELS -o jsonpath='{.items[*].metadata.name}')

  mkdir -p $BACKUP_DIR/disk_io_usage

  for POD in $PODS; do
    node_name=$(kubectl get pod $POD -o jsonpath='{.spec.nodeName}')
    kubectl cp $POD:/var/log/iotop-monitor/usage.log $BACKUP_DIR/disk_io_usage/${node_name}.log || true
  done
}

collect_disk_io_usage

cp /pdt/pod_ips.txt $BACKUP_DIR/pod_ips_${CRS_TASK_NUM}.txt || true
cp /pdt/dns_lookups.txt $BACKUP_DIR/dns_lookups_${CRS_TASK_NUM}.txt || true

API_POD=$(kubectl get pod -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}')

kubectl cp $API_POD:/shared/llm_budget_manager_config.json $BACKUP_DIR/llm_budget_manager_config.json || true
kubectl cp $API_POD:/shared/llm_budget_manager_state.json $BACKUP_DIR/llm_budget_manager_state.json || true
kubectl cp $API_POD:/shared/llm_budget_manager.log $BACKUP_DIR/llm_budget_manager.log || true

cp -r /tmp/pydatatask-emergency $BACKUP_DIR/pydatatask-emergency-${CRS_TASK_NUM} || true

NODE_VIZ_IP=$(kubectl get service node-viz -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)

# Fix buffering issue by forcing line buffering and ensuring buffer flush
# Retry up to 10 times to get valid JSON
for attempt in $(seq 1 10); do
  echo "Attempting to fetch node-viz data (attempt $attempt/10)"
  stdbuf -oL timeout 20 curl -N "http://${NODE_VIZ_IP}:8080/events?" | head -n 5 | tail -n 1 > $BACKUP_DIR/node-viz.json
  sed -i 's/^data: //' $BACKUP_DIR/node-viz.json
  
  # Validate JSON
  if jq . $BACKUP_DIR/node-viz.json > /dev/null 2>&1; then
    echo "Successfully fetched valid JSON from node-viz (attempt $attempt)"
    break
  else
    echo "Invalid JSON received from node-viz (attempt $attempt), retrying..."
    if [ $attempt -eq 10 ]; then
      echo "Failed to get valid JSON from node-viz after 10 attempts"
    fi
  fi
done

date

echo "=== Backing up running tasks ==="
mkdir -p /tmp/ci/long-running
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
  mkdir -p /tmp/ci/long-running

  LIMIT=""
  # if _fuzz in the $TASK, then limit the logs to 50000 lines
  if [[ $TASK =~ _fuzz ]]; then
    LIMIT="--tail 50000"
  fi

  # Get pod logs
  time kubectl logs $POD $LIMIT > $BACKUP_DIR/$TASK.logs/$REPLICANT-$JOB || true
  
  # Record replicant-job
  echo "$REPLICANT-$JOB" >> /tmp/ci/long-running/$TASK

  # Kill the pod as we need to stop any pd task
  # Since we paused the leader, so nothing will get cancelled
  kubectl delete pod $POD --force --grace-period=0 || true
done

date

time /app/local_run/plot_run.py $BACKUP_DIR || true
if [ ! -f /tmp/task_durations.html ]; then
  touch /tmp/task_durations.html
fi

# SEARCH: Service Backup

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

backup_service pydatatask-agent-${CRS_TASK_NUM} pydatatask_agent ${CRS_TASK_NUM}
backup_service api crs_api
for i in $(seq 1 $NUM_CONCURRENT_TASKS); do
  backup_service codeql-$i codeql_server $i
done
for i in $(seq 1 $NUM_CONCURRENT_TASKS); do
  backup_service functionresolver-$i functionresolver_server $i
done
for i in $(seq 1 $NUM_CONCURRENT_TASKS); do
  backup_service analysisgraph-$i analysis_graph $i
done
backup_service litellm litellm
backup_service telemetrydb telemetry_db
backup_service aixcc-server-infra aixcc-server-infra
backup_service permanence permanence_server
#backup_service langserver lang_server


date

function daemonset_logs() {
  DAEMONSET_NAME=$1
  NAMESPACE=default
  # Try with app.kubernetes.io/name first
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
    time kubectl logs $POD --tail 50000 > $BACKUP_DIR/$NAME_NO_DASHES.logs/$POD || true
    echo "$POD" >> /tmp/ci/long-running/$NAME_NO_DASHES
  done
}

daemonset_logs docker-builder
daemonset_logs host-config
daemonset_logs otel-collector
daemonset_logs image-puller
daemonset_logs vllm-server


date

BACKUP_TAR=/tmp/backup-${TARGET_NAME}-${RUN_ID}-${CRS_TASK_NUM}.tar.gz
BACKUP_TAR_ONLY=/tmp/backup-${REAL_TARGET_NAME}-${RUN_ID}.tar.gz

function collect_seeds_from_node() {
  local POD=$1
  NODE_NAME=$(kubectl get pod $POD -o jsonpath='{.spec.nodeName}')
  echo "Collecting seeds from $NODE_NAME"
  kubectl exec $POD -- /bin/bash -c 'du -h /shared/fuzzer_sync/ | sort -h | tail -n 20' || true
  #kubectl exec $POD -- /bin/bash -c 'time tar cfz /shared/fuzzer_sync.tar.gz /shared/fuzzer_sync/ || true' || true
  #sleep 2
  #time kubectl cp $POD:/shared/fuzzer_sync.tar.gz $BACKUP_DIR/fuzzer_sync/$NODE_NAME.tar.gz || true
  #mkdir -p $BACKUP_DIR/fuzzer_sync/$NODE_NAME
  #time tar xf $BACKUP_DIR/fuzzer_sync/$NODE_NAME.tar.gz -C $BACKUP_DIR/fuzzer_sync/$NODE_NAME && rm $BACKUP_DIR/fuzzer_sync/$NODE_NAME.tar.gz
}

function collect_seeds_from_all_nodes() {
  DAEMONSET_NAME="host-config"
  NAMESPACE=default
  LABELS="app.kubernetes.io/name=$DAEMONSET_NAME"
  PODS=$(kubectl get pods -n $NAMESPACE -l $LABELS -o jsonpath='{.items[*].metadata.name}')

  # If no pods found, try with just name
  if [ -z "$PODS" ]; then
    LABELS="name=$DAEMONSET_NAME"
    PODS=$(kubectl get pods -n $NAMESPACE -l $LABELS -o jsonpath='{.items[*].metadata.name}')
  fi

  mkdir -p $BACKUP_DIR/fuzzer_sync/

  for POD in $PODS; do
    (collect_seeds_from_node $POD) &
  done
  wait
  #time tar cfz $BACKUP_DIR/fuzzer_sync.tar.gz $BACKUP_DIR/fuzzer_sync/ --checkpoint=1000
  #time rm -rf $BACKUP_DIR/fuzzer_sync/
}

collect_seeds_from_all_nodes

date

DISKMAN_LOC="web/pipeline-backup/${REAL_TARGET_NAME}/${RUN_ID}"


export STORAGE_URL=https://aixcc-diskman.adamdoupe.com/iKbr6hfymftxL7pr3FEX/pipeline-backup/${REAL_TARGET_NAME}/${RUN_ID}

time /app/local_run/generate_summary.py --target "$REAL_TARGET_NAME" | tee -a "$GITHUB_STEP_SUMMARY"
if [ ! -f /tmp/results.json ]; then
  touch /tmp/results.json
fi


cp /tmp/results.json $BACKUP_DIR/results.json || echo "No results.json"
cp /tmp/results.json $BACKUP_DIR/results_${CRS_TASK_NUM}.json || echo "No results.json"

cp /tmp/task_durations.html $BACKUP_DIR/ || echo "No task_durations.html"

cp $GITHUB_STEP_SUMMARY $BACKUP_DIR/summary.md || echo "No summary.md"
cp $GITHUB_STEP_SUMMARY $BACKUP_DIR/summary_${CRS_TASK_NUM}.md || echo "No summary.md"

cp /pdt/agent.log $BACKUP_DIR/agent_${CRS_TASK_NUM}.log || echo "No agent.log"
cp /pdt/monitor_by_project.log $BACKUP_DIR/monitor_by_project_${CRS_TASK_NUM}.log || echo "No monitor_by_project.log"
cp /pdt/update_project_status.log $BACKUP_DIR/update_project_status_${CRS_TASK_NUM}.log || echo "No update_project_status.log"
cp /pdt/agent-http.log $BACKUP_DIR/agent-http_${CRS_TASK_NUM}.log || echo "No agent-http.log"
cp /pdt/monitor_nodes.log $BACKUP_DIR/monitor_nodes_${CRS_TASK_NUM}.log || echo "No monitor_nodes.log"

rm -rf /pdt/agent-state/nginx_cache || true
cp /pdt/agent-state/ -r $BACKUP_DIR/agent-state/ || echo "No agent-state"
cp /var/log/nginx/ -r $BACKUP_DIR/nginx || echo "No nginx logs"

mkdir -p $BACKUP_DIR/profiling_data/
cp /pdt/profiling_data/* $BACKUP_DIR/profiling_data/ || echo "No profiling_data"
cp /tmp/backup.log $BACKUP_DIR/backup_${CRS_TASK_NUM}.log || echo "No backup.log"

if [ -f /app/infra/agent/scripts/get_llm_usage.sh ]; then
  time /app/infra/agent/scripts/get_llm_usage.sh $BACKUP_DIR/llm_usage.json || echo "No llm_usage.json"
fi

date


chmod 777 -R $BACKUP_DIR

ssh \
  -o StrictHostKeychecking=no \
  -i $GITHUB_WORKSPACE/ci_ssh \
  storage@aixcc-diskman.adamdoupe.com \
  "mkdir -p $DISKMAN_LOC"

scp \
  -o StrictHostKeychecking=no \
  -i $GITHUB_WORKSPACE/ci_ssh \
  $BACKUP_DIR/*.{md,dot,html,json} \
  storage@aixcc-diskman.adamdoupe.com:$DISKMAN_LOC/. || true

rm -rf /tmp/crs_scratch
mkdir /tmp/crs_scratch
SUBMITTER_POD=$(kubectl get pod -l task=submitter -o jsonpath='{.items[0].metadata.name}')

time kubectl cp $SUBMITTER_POD:/crs_scratch /tmp/crs_scratch/ --retries 5
pushd /tmp/
tar cfz $BACKUP_DIR/crs_scratch.tar.gz crs_scratch
popd

date

rm -rf /tmp/analysisgraph
mkdir /tmp/analysisgraph
ANALYSIS_GRAPH_POD=$(kubectl get pod -l app.kubernetes.io/name=analysisgraph-${CRS_TASK_NUM} -o jsonpath='{.items[0].metadata.name}')

# ⬇️ Replaces kubectl cp and follows symlinks
time kubectl exec "$ANALYSIS_GRAPH_POD" -- \
    tar --dereference -C / -cf - var/lib/neo4j | tar -C /tmp/analysisgraph -xf -

pushd /tmp/
time tar cfz $BACKUP_DIR/analysisgraph_${CRS_TASK_NUM}.tar.gz analysisgraph --checkpoint=1000
popd

date

rm -rf /tmp/permanence
mkdir /tmp/permanence
PERMANENCE_SERVER_POD=$(kubectl get pod -l app.kubernetes.io/name=permanence -o jsonpath='{.items[0].metadata.name}')
time kubectl cp $PERMANENCE_SERVER_POD:/data /tmp/permanence/ --retries 5 2>/dev/null
pushd /tmp/
time tar cfz $BACKUP_DIR/permanence.tar.gz permanence --checkpoint=1000
popd

pushd $BACKUP_DIR

chmod +x $ROOT_DIR/infra/agent/scripts/ci/look_for_problems.sh || true
time timeout 10m $ROOT_DIR/infra/agent/scripts/ci/look_for_problems.sh \
  $BACKUP_DIR/problem_ctx_${CRS_TASK_NUM}.md \
  $BACKUP_DIR/problem_diagnosis_${CRS_TASK_NUM}.md \
  $BACKUP_DIR/problem_thinking_${CRS_TASK_NUM}.md \
  2>$BACKUP_DIR/look_for_problems_${CRS_TASK_NUM}.log || true

cp $BACKUP_DIR/problem_ctx_${CRS_TASK_NUM}.md $BACKUP_DIR/problem_ctx.md || true
cp $BACKUP_DIR/problem_diagnosis_${CRS_TASK_NUM}.md $BACKUP_DIR/problem_diagnosis.md || true
cp $BACKUP_DIR/problem_thinking_${CRS_TASK_NUM}.md $BACKUP_DIR/problem_thinking.md || true

echo $'\n# Claude Diagnosis\n' >> $GITHUB_STEP_SUMMARY

echo $'<details>\n<summary>Claude Thinking</summary>\n' >> $GITHUB_STEP_SUMMARY
cat $BACKUP_DIR/problem_thinking.md | sed 's/</{/g' >> $GITHUB_STEP_SUMMARY
echo $'</details>\n' >> $GITHUB_STEP_SUMMARY

cat $BACKUP_DIR/problem_diagnosis.md | sed 's/</{/g' >> $GITHUB_STEP_SUMMARY


# Some artifacts are way too large!

function remove_artifacts() {
  # Iterate over all files and replace them with a text file that says "artifact too large"
  local ARTIFACTS_DIR=$1
  for FILE in $(find $ARTIFACTS_DIR -type f); do
    FILE=$(realpath $FILE)
    echo "Artifact excluded from backup due to size of $(du -sh $FILE | cut -f1)" > $FILE
  done
}

#remove_artifacts $BACKUP_DIR/oss_fuzz_project_build.project_build_artifacts
#remove_artifacts $BACKUP_DIR/oss_fuzz_project_build.project_run_artifacts
#remove_artifacts $BACKUP_DIR/oss_fuzz_project_run.project_volumes_id
#remove_artifacts $BACKUP_DIR/aflrun_build.aflrun_build_artifacts


popd

cp /tmp/backup.log $BACKUP_DIR/backup.log || echo "No backup.log"

date

du -h $BACKUP_DIR | sort -h | tail -n 10 || true

# Check backup directory size before upload
BACKUP_SIZE_GB=$(du -s --block-size=1G $BACKUP_DIR | cut -f1)
echo "Backup directory size: ${BACKUP_SIZE_GB}GB"

if [ $BACKUP_SIZE_GB -gt 40 ]; then
  echo "=============================================="
  echo "ERROR: BACKUP SIZE TOO LARGE: ${BACKUP_SIZE_GB}GB"
  echo "MAXIMUM ALLOWED: 40GB"
  echo "ABORTING BACKUP TO PREVENT ISSUES"
  echo "=============================================="
  exit 1
elif [ $BACKUP_SIZE_GB -gt 25 ]; then
  echo "WARNING: Backup size is ${BACKUP_SIZE_GB}GB (over 25GB threshold)"
fi

# Initially upload everything we have, we will make the tar after as it is slow
time rsync -e "ssh -o StrictHostKeychecking=no -i $GITHUB_WORKSPACE/ci_ssh" \
 -az \
 --ignore-existing \
 --exclude="aflpp_fuzz_merge.benigns_dir" \
 --exclude="aflpp_fuzz_merge.benigns_dir.meta" \
 --exclude="aflpp_fuzz_merge.crashes" \
 --exclude="aflpp_fuzz_merge.crashes.meta" \
 $BACKUP_DIR/ \
 storage@aixcc-diskman.adamdoupe.com:web/pipeline-backup/${REAL_TARGET_NAME}/${RUN_ID}

date

# Remove files we don't want in the final tar
time rm -rf $BACKUP_DIR/fuzzer_sync* || true

date
pushd $(dirname $BACKUP_DIR)
time tar cfz $BACKUP_TAR ./$(basename $BACKUP_DIR) --checkpoint=1000
popd

ls -h $BACKUP_TAR || true

mv $BACKUP_TAR $BACKUP_DIR/

TAR_NAME=$(basename $BACKUP_TAR)
MAIN_TAR_NAME=$(basename $BACKUP_TAR_ONLY)

cp /tmp/backup.log $BACKUP_DIR/backup_${CRS_TASK_NUM}.log || echo "No backup.log"

time python $(dirname $0)/backup_llm_cost.py $BACKUP_DIR/llm_cost.json || echo "No llm_cost.json"

date

# Backup telemetry db
kubectl exec $TELEMETRY_DB_POD -- influx backup /tmp/telemetry_db -t shellphish-influxdb-token
kubectl cp $TELEMETRY_DB_POD:/tmp/telemetry_db /tmp/telemetry_db --retries 5
pushd /tmp 
time tar --owner=1000 --group=1000 -czf $BACKUP_DIR/telemetry-${TARGET_NAME}-${RUN_ID}.tar.gz telemetry_db --checkpoint=1000
popd

# Backup signoz
time kubectl exec $AIXCC_SERVER_INFRA_POD -- /infra/backup_signoz.sh || true
time kubectl cp $AIXCC_SERVER_INFRA_POD:/shared/signoz-backup.tar.gz /tmp/signoz-backup.tar.gz --retries 5 || true
cp /tmp/signoz-backup.tar.gz $BACKUP_DIR/signoz-${TARGET_NAME}-${RUN_ID}.tar.gz || true

date

time rsync -e "ssh -o StrictHostKeychecking=no -i $GITHUB_WORKSPACE/ci_ssh" \
  -az \
  --ignore-existing \
  $BACKUP_DIR/ \
  storage@aixcc-diskman.adamdoupe.com:web/pipeline-backup/${REAL_TARGET_NAME}/${RUN_ID}

# symlink the backup tar to the latest backup
ssh \
  -o StrictHostKeychecking=no \
  -i $GITHUB_WORKSPACE/ci_ssh \
  storage@aixcc-diskman.adamdoupe.com \
  "ln -s ./${TAR_NAME} web/pipeline-backup/${REAL_TARGET_NAME}/${RUN_ID}/${MAIN_TAR_NAME};" || true

date

#rm -rf $tmpdir

echo "Backup complete"

touch /tmp/.backup_complete

pkill -f /tmp/backup.log || true

cp /tmp/backup.log $BACKUP_DIR/backup_${CRS_TASK_NUM}.log || echo "No backup.log"
cp $BACKUP_DIR/backup_${CRS_TASK_NUM}.log $BACKUP_DIR/backup.log || echo "No backup.log"

time scp \
  -o StrictHostKeychecking=no \
  -i $GITHUB_WORKSPACE/ci_ssh \
  $BACKUP_DIR/backup_${CRS_TASK_NUM}.log \
  storage@aixcc-diskman.adamdoupe.com:$DISKMAN_LOC/. || true
