FROM ubuntu:latest as base

RUN apt-get update -y && apt-get upgrade -y && \
    apt-get install -y python3-pip \
    curl wget git diffutils clang gcc jq sudo 

WORKDIR /app
RUN pip install tomli
ADD pyproject.toml /app/pyproject.toml

# Install dependencies without installing the app itself
RUN python3 -c \
'import tomli; \
open("/app/requirements.txt", "w") \
.write("\n".join( \
    tomli.load(\
        open("pyproject.toml","rb") \
    )["project"]["dependencies"] \
))' \
&& pip install -r /app/requirements.txt \
&& rm requirements.txt

FROM base as debug
RUN pip install debugpy

FROM base as runner
