#!/bin/bash
set -e

export ARCH=x86_64
export BUILDER_SCRIPT=appimage-builder.yml

./ubuntu_build.sh