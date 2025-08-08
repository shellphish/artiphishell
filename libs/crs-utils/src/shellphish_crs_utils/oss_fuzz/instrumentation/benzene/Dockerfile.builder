ARG BASE_IMAGE=
FROM ${BASE_IMAGE} AS final-builder

RUN mkdir -p $SRC/shellphish

RUN mv /usr/bin/ld /usr/bin/ld.real
COPY anti-wrap-ld.sh /usr/bin/ld
RUN chmod +x /usr/bin/ld

COPY compile_benzene /usr/local/bin/
COPY generic_harness.c $SRC/shellphish/