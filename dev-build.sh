#!/usr/bin/env bash

while sleep 1; do
    ag -l | entr -cdrs 'docker build -t appthreat/sast-scan -f Dockerfile-dev .'
done
