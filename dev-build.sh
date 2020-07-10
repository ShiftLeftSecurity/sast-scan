#!/usr/bin/env bash
DOCKER_CMD=docker
if command -v podman >/dev/null 2>&1; then
    DOCKER_CMD=podman
fi
python3 -m black .
python3 -m black scan
isort **/*.py
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --statistics

$DOCKER_CMD build -t shiftleft/sast-scan -t shiftleft/scan -f Dockerfile .
$DOCKER_CMD build -t shiftleft/scan-java -f ci/Dockerfile-java .
$DOCKER_CMD build -t shiftleft/scan-slim -f ci/Dockerfile-dynamic-lang .
$DOCKER_CMD build -t shiftleft/scan-csharp -f ci/Dockerfile-csharp .
$DOCKER_CMD build -t shiftleft/scan-oss -f ci/Dockerfile-oss .
