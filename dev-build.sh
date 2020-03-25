#!/usr/bin/env bash

while sleep 1; do
    ag -l | entr -cdrs 'docker build -t shiftleft/sast-scan -f Dockerfile .'
done
