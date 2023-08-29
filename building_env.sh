#!/usr/bin/env bash
export GOSEC_VERSION=2.17.0
export TFSEC_VERSION=1.28.1
export KUBESEC_VERSION=2.13.0
export KUBE_SCORE_VERSION=1.17.0
export DETEKT_VERSION=1.23.1
export GITLEAKS_VERSION=8.17.0
export SC_VERSION=2023.1.5 # 0.4.5, staticcheck actually uses date versions now
export PMD_VERSION=6.55.0
export FSB_VERSION=1.12.0
export SB_CONTRIB_VERSION=7.4.7
export SB_VERSION=4.7.3
export NODE_VERSION=18.17.1


## Fail if ARCH is not set
if [ -z "$ARCH" ]; then
    echo "ARCH is not set, please set it to the architecture you want to build for"
    exit 1
fi


# Normalize in case of docker invocation using TARGETARCH
if [ "$ARCH" = "amd64" ]; then # docker uses this but lets normalize
	ARCH="x86_64"
fi
if [ "$ARCH" = "arm64" ]; then # docker uses this but lets normalize
	ARCH="aarch64"
fi

# Account for non conventional Arch names in downloadables
if [ "$ARCH" = "x86_64" ]; then
    NODE_ARCH="x64"
else
    NODE_ARCH="$ARCH"
fi
if [ "$ARCH" = "x86_64" ]; then
    ARCH_ALT_NAME="amd64"
else
    ARCH_ALT_NAME="$ARCH"
fi
if [ "$ARCH" = "aarch64" ]; then
    LIBARCH="arm64"
else
    LIBARCH="$ARCH"
fi

export NODE_ARCH
export ARCH_ALT_NAME
export LIBARCH


## mayberm deletes the passed file only if KEEP_BUILD_ARTIFACTS variable is not set
mayberm() {
    if [ -z "$KEEP_BUILD_ARTIFACTS" ]; then
        rm "$1"
    fi
}
