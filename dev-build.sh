#!/usr/bin/env bash

while sleep 1; do
    ag -l lib | entr -cdrs 'docker build -t appthreat/sast-scan -f Dockerfile .'
done
