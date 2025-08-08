#!/bin/bash

set -ex


#curl -u $COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN -X 'POST' 'https://api.aixcc.tech/v1/request/delta/' -H 'Content-Type: application/json' -d '{"duration_secs": 1800 }'

#export TG=ex3-tk-delta-01
#export TG=ex3-tk-delta-03



#export TG=ex3-ex-delta-01
#export TG=ex3-sq-delta-02
#export TG=ex3-lx-delta-01
#export TG=ex3-cu-delta-01
#export TG=ex3-cc-delta-02
export TG=ex3-tk-delta-02 # sarif


#0197418ad67575339d639050f5b0bd7d/pipeline/pipeline_input.sarif_report/019742d33bd375f0a0abd0c9c7ad9e40



curl -u "$COMPETITION_API_KEY_ID:$COMPETITION_API_KEY_TOKEN" -X 'POST' "https://api.aixcc.tech/v1/request/$TG/" --json '{"duration_secs":18000}' -v