#!/usr/bin/env bash

docker build -t shiftleft/sast-scan -t shiftleft/scan -f Dockerfile .
docker build -t shiftleft/scan-java -f ci/Dockerfile-java .
docker build -t shiftleft/scan-csharp -f ci/Dockerfile-csharp .
docker build -t shiftleft/scan-oss -f ci/Dockerfile-oss .
docker build -t shiftleft/scan-slim -f ci/Dockerfile-dynamic-lang .
