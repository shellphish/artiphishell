# aixcc-no-build: aixcc-patchery
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
      # install native deps
      clang-14 rsync wget curl git jq python3-dev python3-venv python3-pip python-is-python3 vim psmisc git \
      apt-transport-https ca-certificates curl software-properties-common && \
      # install yq
      wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && \
      chmod +x /usr/bin/yq && \
      # install docker
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
      add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
      apt-get update && \
      apt-get -y install docker-ce && \
      # install virtme for kernel testing
      add-apt-repository -y ppa:arighi/virtme-ng && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y virtme-ng libvirt-daemon-system && \
      # config git
      git config --global user.email "example@example.com" && \
      git config --global user.name "jane doe"

# setup agentlib and clang_indexer
RUN git config --global credential.helper 'store --file ~/.git-credentials' && \
  echo 'https://git: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@github.com' > ~/.git-credentials && \
  git clone https://github.com/shellphish-support-syndicate/agentlib.git /agentlib && \
  pip install -e /agentlib

# setup patchery
COPY patchery /patchery/patchery
COPY setup.cfg /patchery/setup.cfg
COPY setup.py /patchery/setup.py
WORKDIR /patchery
RUN pip install -e .[test]

# debugging env
ENV LOG_LLM=0
ENV LOG_LEVEL=WARNING
ENV PYTHONBREAKPOINT=ipdb.set_trace
ENV AGENTLIB_SAVE_FILES=off
# setup env
ENV OPENAI_API_KEY="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"
ENV GOOGLE_API_KEY="AIzaSyDOeG3LqRyhLm5NG0B5FtOUPb3K6sZKT4g"
ENV ANTHROPIC_API_KEY="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"
ENV LITELLM_KEY='sk-artiphishell'
ENV AIXCC_LITELLM_HOSTNAME='http://beatty.unfiltered.seclab.cs.ucsb.edu:4000'
ENV RETRIEVAL_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:48751'
ENV EMBEDDING_API='http://beatty.unfiltered.seclab.cs.ucsb.edu:49152'
ENV MODEL="oai-gpt-4o"
ENV SRC="/tmp/src"
ENV CRASHES="/tmp/crashes"
ENV OUT="/tmp/out"
RUN mkdir -p ${SRC} ${CRASHES} ${OUT}
