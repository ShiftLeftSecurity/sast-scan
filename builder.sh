#!/usr/bin/env bash

docker run -v `pwd`:/build shiftleft/sast-scan-builder
