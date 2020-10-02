#!/usr/bin/env bash

set -e

GIT_HASH=$(git rev-parse HEAD)
GIT_TAG=$(git describe --tags)
DOCKER_BASE_HASH=$(date -u +%F)

docker run -v `pwd`:/build shiftleft/sast-scan-builder

mv scan-latest-x86_64.AppImage scan-$GIT_TAG-x86_64.AppImage
