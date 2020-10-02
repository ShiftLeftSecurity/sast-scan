#!/usr/bin/env bash

set -e

GIT_HASH=$(git rev-parse HEAD)
GIT_TAG=$(git describe --tags)
DOCKER_BASE_HASH=$(date -u +%F)

docker build \
       -t shiftleft/sast-scan-builder:latest \
       -t shiftleft/sast-scan-builder:$GIT_TAG \
       -t shiftleft/sast-scan-builder:$GIT_HASH \
       -t shiftleft/sast-scan-builder:$DOCKER_BASE_HASH \
       --label git.tag=$GIT_TAG \
       --label git.hash=$GIT_HASH \
       --label git.project=sast-scan \
       --label git.clone-url=git@github.com:ShiftLeftSecurity/sast-scan.git \
       --label git.github-url=https://github.com/ShiftLeftSecurity/sast-scan \
       -f builder.Dockerfile .

docker push shiftleft/sast-scan-builder:latest
docker push shiftleft/sast-scan-builder:$GIT_TAG
docker push shiftleft/sast-scan-builder:$GIT_HASH
docker push shiftleft/sast-scan-builder:$DOCKER_BASE_HASH
