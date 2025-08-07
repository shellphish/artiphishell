#!/usr/bin/env bash

cd "$(dirname "$0")" || { echo "huh?" && exit 1; }
. /root/venv/bin/activate

EXTRA_FLAGS="--global-script-env DOCKER_HOST_ORIG=$DOCKER_HOST"
VERB="${VERB-run --forever}"

# set up resource limits
if [[ -S /var/run/docker.sock ]]; then
    yq -i '.max_job_quota = null' ../../pipeline.lock
elif [[ -e /var/run/secrets/kubernetes.io ]]; then
    ALL_CPU="$(kubectl get nodes -o yaml | yq '.items | map(.status.capacity.cpu | to_number) | .[] as $item ireduce (0; . + $item)')"
    ONE_CPU="$(kubectl get nodes -o yaml | yq '.items.0.status.capacity.cpu | to_number')"
    ALL_MEM="$(kubectl get nodes -o yaml | yq '.items | map(.status.capacity.memory as $mem | ({"Ki": 1024, "Mi": 1024*1024, "Gi": 1024*1024*1024, "k": 1000, "M": 1000*1000}.[$mem | match("Ki$|Mi$|Gi$|k$|M$|G$").string]) * ($mem | match("[[:digit:]]*").string | to_number)) | .[] as $item ireduce (0; . + $item)')"
    ONE_MEM="$(kubectl get nodes -o yaml | yq '.items.0.status.capacity.memory as $mem | ({"Ki": 1024, "Mi": 1024*1024, "Gi": 1024*1024*1024, "k": 1000, "M": 1000*1000}.[$mem | match("Ki$|Mi$|Gi$|k$|M$|G$").string]) * ($mem | match("[[:digit:]]*").string | to_number)')"
    yq -i ".max_job_quota = {\"cpu\": $((ONE_CPU - 6)), \"mem\": $((ONE_MEM - 2*1024*1024*1024))}" ../../pipeline.lock
    yq -i ".executors.*.args.kube_quota = {\"cpu\": $((ALL_CPU - 20)), \"mem\": $((ALL_MEM - 16*1024*1024*1024))}" ../../pipeline.lock
fi

# set up task docker environment
if [[ -S /var/run/docker.sock ]]; then
    # we are not going to be launching triple-dind, so tasks may use the orgs dind
    EXTRA_FLAGS+=" --global-script-env DOCKER_HOST=$DOCKER_HOST"
    EXTRA_FLAGS+=" --global-template-env DOCKER_HOST=$DOCKER_HOST"
    EXTRA_FLAGS+=" --global-script-env DOCKER_SYNC="
    # we DEFINITELY want pd run to be operating with the original /var/run/docker.sock, not tcp://dind
    unset DOCKER_HOST
elif [[ -e /var/run/secrets/kubernetes.io ]]; then
    yq -i ".spec.containers.[0].resources.limits.cpu = \"$ONE_CPU\"" docker-api.yaml
    yq -i ".spec.containers.[0].resources.limits.memory = \"$ONE_MEM\"" docker-api.yaml
    kubectl apply -f docker-api.yaml --validate=false
else
    echo "Not running in docker or kubernetes???"
    exit 1
fi

# set up scratch environment
if [[ -S /var/run/docker.sock ]]; then
    SCRATCH_PATH="$(docker inspect $HOSTNAME | jq -r '.[0].Mounts | map(select(.Destination == "'"$AIXCC_CRS_SCRATCH_SPACE"'")) | .[0].Source')"
    yq -i '.executors.*.args.kube_volumes."/crs_scratch" = {"host_path": "'"$SCRATCH_PATH"'"}' ../../pipeline.lock
    yq -i '.executors.*.args.kube_volumes."/shared" = {"host_path": "'"$SCRATCH_PATH"'"}' ../../pipeline.lock
elif [[ -e /var/run/secrets/kubernetes.io ]]; then
    SCRATCH_PVC="$(kubectl get pods $HOSTNAME -o yaml | yq '(.spec.containers.0.volumeMounts | filter(.mountPath == "'"$AIXCC_CRS_SCRATCH_SPACE"'") | .0.name) as $name | .spec.volumes | filter(.name == $name) | .0.persistentVolumeClaim.claimName')"
    yq -i '.executors.*.args.kube_volumes."/crs_scratch" = {"pvc": "'"$SCRATCH_PVC"'"}' ../../pipeline.lock
fi


pd --verbose \
    --global-script-env AIXCC_LITELLM_HOSTNAME=$AIXCC_LITELLM_HOSTNAME \
    --global-script-env AIXCC_API_HOSTNAME=$AIXCC_API_HOSTNAME \
    --global-script-env AIXCC_CP_ROOT=$AIXCC_CP_ROOT \
    --global-script-env AIXCC_CRS_SCRATCH_SPACE=$AIXCC_CRS_SCRATCH_SPACE \
    --global-script-env LITELLM_KEY=$LITELLM_KEY \
    --global-script-env CAPI_ID=$CAPI_ID \
    --global-script-env CAPI_TOKEN=$CAPI_TOKEN \
    --global-script-env ABSOLUTELY_NO_INTERNET=1 \
    --global-script-env RETRIEVAL_API=http://retrieval-api:48751 \
    --global-script-env EMBEDDING_API=http://embedding-api:49152 \
    --debug-trace \
    $EXTRA_FLAGS \
    $VERB
