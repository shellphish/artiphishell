#!/bin/bash

docker pull ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base:latest
docker pull ghcr.io/shellphish-support-syndicate/aixcc-component-base:latest

docker tag ghcr.io/shellphish-support-syndicate/aixcc-dependencies-base:latest aixcc-dependencies-base:latest
docker tag aixcc-dependencies-base:latest artiphishelltiny.azurecr.io/aixcc-dependencies-base:latest
docker tag ghcr.io/shellphish-support-syndicate/aixcc-component-base:latest aixcc-component-base:latest
docker tag aixcc-component-base:latest artiphishelltiny.azurecr.io/aixcc-component-base:latest
docker tag aixcc-libs:latest artiphishelltiny.azurecr.io/aixcc-libs:latest