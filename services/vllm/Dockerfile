FROM nvidia/cuda:12.6.3-runtime-ubuntu22.04
RUN apt-get update && apt-get install curl git ca-certificates nvtop -y

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin/:$PATH"
RUN uv venv --python 3.12 --seed
ENV PATH="/app/.venv/bin:$PATH"

ENV VLLM_VERSION=0.9.1
ENV PYTHON_VERSION=38

RUN uv pip install \
      https://github.com/vllm-project/vllm/releases/download/v${VLLM_VERSION}/vllm-${VLLM_VERSION}+cu126-cp${PYTHON_VERSION}-abi3-manylinux1_x86_64.whl \
      --extra-index-url https://download.pytorch.org/whl/cu126 \
      --index-strategy unsafe-best-match

RUN apt-get update \
      && apt-get install -y --no-install-recommends build-essential \
      && rm -rf /var/lib/apt/lists/*
      
ADD server.sh /app/server.sh
RUN chmod +x /app/server.sh

ENTRYPOINT ["/app/server.sh"]
