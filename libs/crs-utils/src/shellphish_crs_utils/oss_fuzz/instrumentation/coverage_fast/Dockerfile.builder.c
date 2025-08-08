ARG BASE_IMAGE=
FROM ${BASE_IMAGE} AS aflpp-afl-compile-base
ENV DEBIAN_FRONTEND=noninteractive
# RUN apt update && apt install -y libglib2.0-dev libunwind-dev


RUN mkdir -p $SRC/shellphish
RUN mkdir -p $SRC/shellphish/pintracer
# RUN mkdir -p $SRC/shellphish/riotracer
RUN mkdir -p /shellphish/blobs
# tracer's file live there, pin does not

# get RIO and build libraries
# RUN wget https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Linux-11.3.0.tar.gz -O /shellphish/blobs/rio.tar.gz
# RUN cd /shellphish/blobs/ && tar -xzf ./rio.tar.gz
# RUN cd /shellphish/blobs/DynamoRIO-Linux-11.3.0-1/samples && cmake . && cmake --build .
# copy RIO TOOL 
# COPY ./rio-tracer/tracer.c $SRC/shellphish/riotracer/
# COPY ./rio-tracer/CMakeLists.txt $SRC/shellphish/riotracer
# bulid RIO TOOL 
# RUN cd $SRC/shellphish/riotracer && CC=cc CXX=cc  cmake -DDynamoRIO_DIR=/shellphish/blobs/DynamoRIO-Linux-11.3.0-1/cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="" -DCMAKE_CXX_FLAGS="" -DCMAKE_CXX_FLAGS_RELEASE="-O3" . && cmake --build . --verbose

# replace LD
RUN mv /usr/bin/ld /usr/bin/ld.real
COPY anti-wrap-ld.sh /usr/bin/ld
RUN chmod +x /usr/bin/ld

# Compile the sigsev condom
COPY sigsegv_condom.c sigsegv_condom.c
RUN gcc -o sigsegv_condom sigsegv_condom.c -ldl
RUN cp sigsegv_condom $SRC/shellphish/
RUN md5sum $SRC/shellphish/sigsegv_condom

# Replacing the compile script
RUN cp /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile-c /usr/local/bin/compile
RUN chmod +x /usr/local/bin/compile

# PINTOOL
COPY ./pintool-tracer/fun-q-lo.cpp $SRC/shellphish/pintracer/fun-q-lo.cpp
COPY ./pintool-tracer/makefile.rules $SRC/shellphish/pintracer/makefile.rules
COPY ./pintool-tracer/makefile $SRC/shellphish/pintracer/makefile

# PIN
RUN wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz -O /shellphish/blobs/pin.tar.gz
RUN cd /shellphish/blobs/ && tar -xzf ./pin.tar.gz

# COPY PIN AND RIO
RUN cp -r /shellphish/blobs/pin-external-3.31-98869-gfa6f126a8-gcc-linux $OUT/pin
# RUN cp -r /shellphish/blobs/DynamoRIO-Linux-11.3.0-1 $OUT/dynamorio

ENV PIN_ROOT $OUT/pin
# ENV DR_BUILD=$OUT/dynamorio/
# ENV DR_ROOT=$OUT/dynamorio/

RUN cd $SRC/shellphish/pintracer/ &&  make clean && make CC=/usr/bin/gcc CXX=/usr/bin/g++
