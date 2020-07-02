#!/usr/bin/env bash
DOCKER_CMD=docker
if command -v podman >/dev/null 2>&1; then
    DOCKER_CMD=podman
fi
python3 -m black .
python3 -m black scan
isort **/*.py
$DOCKER_CMD build -t shiftleft/sast-scan -t shiftleft/scan -f Dockerfile .
$DOCKER_CMD build -t shiftleft/scan-java -f ci/Dockerfile-java .
$DOCKER_CMD build -t shiftleft/scan-slim -f ci/Dockerfile-dynamic-lang .
$DOCKER_CMD build -t shiftleft/scan-csharp -f ci/Dockerfile-csharp .
$DOCKER_CMD build -t shiftleft/scan-oss -f ci/Dockerfile-oss .
