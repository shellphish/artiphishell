# aixcc-build: aixcc-corpusguy

# this image comes with crs-utils
# to build aixcc-component-base locally cd to shellphish-crs/pipelines/local_run and run rebuild_local.sh

ARG IMAGE_PREFIX=
ARG SOURCE_REPO=https://github.com/shellphish-support-syndicate/artiphishell

####################################################################################################
####################################################################################################
FROM ${IMAGE_PREFIX}aixcc-component-base as corpusguy-base
LABEL org.opencontainers.image.source=${SOURCE_REPO}

RUN pip3 install pyyaml dnspython unidiff
COPY . /shellphish/corpusguy/

RUN mkdir -p /shellphish/dictionaries && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/dictionaries-v3.tar -o /shellphish/dictionaries.tar && \
    tar -xf /shellphish/dictionaries.tar -C /shellphish/dictionaries && \
    rm /shellphish/dictionaries.tar

RUN mkdir -p /shellphish/corpus-unfiltered && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/corpus-unfiltered-v3.tar -o /shellphish/corpus-unfiltered.tar && \
    tar -xf /shellphish/corpus-unfiltered.tar -C /shellphish/corpus-unfiltered && \
    rm /shellphish/corpus-unfiltered.tar
    
RUN mkdir -p /shellphish/corpus-filtered && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/corpus-filtered-v3.tar -o /shellphish/corpus-filtered.tar && \
    tar -xf /shellphish/corpus-filtered.tar -C /shellphish/corpus-filtered && \
    rm /shellphish/corpus-filtered.tar

RUN mkdir -p /shellphish/corpus-kickstart && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/corpus-kickstart-v3.tar -o /shellphish/corpus-kickstart.tar && \
    tar -xf /shellphish/corpus-kickstart.tar -C /shellphish/corpus-kickstart && \
    rm /shellphish/corpus-kickstart.tar

RUN mkdir -p /shellphish/corpus-kickstart-crashes && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/corpus-kickstart-crashes-v4.tar -o /shellphish/corpus-kickstart-crashes.tar && \
    tar -xf /shellphish/corpus-kickstart-crashes.tar -C /shellphish/corpus-kickstart-crashes && \
    rm /shellphish/corpus-kickstart-crashes.tar

RUN mkdir -p /shellphish/corpus-grammars && \
    curl http://beatty.unfiltered.seclab.cs.ucsb.edu:8000/corpus-grammars-v4.tar -o /shellphish/corpus-grammars.tar && \
    tar -xf /shellphish/corpus-grammars.tar -C /shellphish/corpus-grammars && \
    rm /shellphish/corpus-grammars.tar