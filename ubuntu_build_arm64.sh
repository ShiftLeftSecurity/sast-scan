#!/bin/bash
set -e

export ARCH=aarch64
export BUILDER_SCRIPT=appimage-builder-arm64.yml

./ubuntu_build.sh