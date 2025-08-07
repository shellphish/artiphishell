# ONE DOCKERFILE TO RULE THEM ALL

ARG IMAGE_PREFIX=
FROM ${IMAGE_PREFIX}aixcc-component-base:latest
# silly docker
ARG IMAGE_PREFIX=
RUN apt-get update && apt-get install -y make gcc g++ libgraphviz-dev
RUN python3 -m venv /root/venv

ADD ./meta-components/pydatatask/pyproject.toml ./meta-components/pydatatask/setup.py /root/pipelines/meta-components/pydatatask/
RUN cd /root/pipelines/meta-components/pydatatask && mkdir pydatatask && echo '__version__ = "0.0.0"' >pydatatask/__init__.py && /root/venv/bin/pip install -e . pygraphviz yappi
ADD ./meta-components/pydatatask /root/pipelines/meta-components/pydatatask
RUN /root/venv/bin/pip install -e /root/pipelines/meta-components/pydatatask

# this nonsense could maybe be replaced with pdl inlining all the pipeline.yamls into pipeline.lock?
# maybe even should?
RUN --mount=src=./,target=/mnt cd /mnt && find . -name '*pipeline*.y*ml' | while read -r filepath; do echo $filepath && mkdir -p /root/pipelines/$(dirname $filepath) && cp /mnt/$filepath /root/pipelines/$filepath && if grep ^tasks: /root/pipelines/$filepath >/dev/null; then yq -i '.tasks.*.cache_dir = "/shared/__DONT_TOUCH_cache" | .tasks.*.executable.args.mounts.["/shared/"] = "/shared/"' /root/pipelines/$filepath; fi; done

RUN cd /root/pipelines && \
  /root/venv/bin/pdl \
    --name aixcc \
    --repo-meta-mongo-s3-fallback mongodb://admin:hackharder@mongo:::aixcc:::::http://admin:hackharder@minio:9000/aixcc \
    --repo-blob-s3 http://admin:hackharder@minio:9000/aixcc \
    --repo-fs-s3 http://admin:hackharder@minio:9000/aixcc \
    --exec-local-or-kube kube_quota=192/768Gi,kube_volumes=/crs_scratch:Pvc@crs-scratch::/shared:HostPath@/shared::/var/run/docker.sock:Null \
    --max-job-quota 62/250Gi \
    --no-launch-agent --no-lockstep \
    --agent-host agent \
    --agent-port 9595 \
    --image-prefix "${IMAGE_PREFIX}" \
    --global-template-env IMAGE_PREFIX=${IMAGE_PREFIX} \
    --global-template-env DOCKER_IMAGE_PREFIX=${IMAGE_PREFIX} \
    --global-script-env DOCKER_SYNC='http://$NODE_IP:7677/sync' \
    --global-script-env DOCKER_HOST='tcp://$NODE_IP:7523' \
    --global-template-env DOCKER_HOST='tcp://$NODE_IP:7523' \
    --global-script-env DOCKER_EXTRA_ARGS_SHELLPHISH='"--cpu-period=100000 --cpu-quota=$CPU_QUOTA --memory=$MEM_QUOTA"'

ADD ./meta-components/leader-scripts/leader.sh /root/pipelines/meta-components/leader-scripts/
ADD ./meta-components/leader-scripts/agent.sh /root/pipelines/meta-components/leader-scripts/
ADD ./meta-components/leader-scripts/ingest.sh /root/pipelines/meta-components/leader-scripts/
ADD ./meta-components/leader-scripts/logs.py /root/pipelines/meta-components/leader-scripts/
ADD ./meta-components/leader-scripts/docker-api.yaml /root/pipelines/meta-components/leader-scripts/
ADD ./meta-components/leader-scripts/dockerparse.py /root/pipelines/meta-components/leader-scripts/

RUN echo "source /root/venv/bin/activate" >> /root/.bashrc
WORKDIR /root/pipelines
