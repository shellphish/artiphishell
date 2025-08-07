#!/bin/bash

TARGET_MAKE="${TARGET_MAKE:=mock-cp jenkins-cp nginx-cp}"

for MAKE_CMD in $TARGET_MAKE
do
    case $MAKE_CMD in
        mock-cp | jenkins-cp | nginx-cp)
            make $MAKE_CMD
            ;;
        *)
            # Copy shit from the repo
            ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
            HOST_CAPI_LOGS = $(ROOT_DIR)/capi_logs
            HOST_CP_ROOT_DIR = $(ROOT_DIR)/cp_root
            VOLUMES = $(HOST_CAPI_LOGS) $(HOST_CP_ROOT_DIR)
            mkdir -p $(VOLUMES)
            rm -rf $(HOST_CP_ROOT_DIR)/$@
	        git clone git@github.com:aixcc-sc/challenge-002-jenkins-cp.git $(HOST_CP_ROOT_DIR)/$@
	        cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare
            ;;
    esac
done
