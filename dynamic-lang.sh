#!/bin/bash

# Dynamic lang script installs a subset of the whole tools required by scan application, this is the set used by
# scan-slim image.
# This can be invoked standalone passing the path to the folder where the binaries will be installed, or it can be
# sourced by another script, in which case the USR_BIN_PATH variable will be set to the path where the binaries go.

# IF USR_BIN_PATH is not set, set it to the default, this means we are being called standalone.
if [ -z "$USR_BIN_PATH" ]; then
	source building_env.sh
	# typically "/usr/local/bin/shiftleft/"
    USR_BIN_PATH=$1
fi
export USR_BIN_PATH

mkdir -p ${USR_BIN_PATH}


## Download and install gitleaks (https://github.com/zricethezav/gitleaks)
GLEAKS_FOLDER="gitleaks_${GITLEAKS_VERSION}_linux_${NODE_ARCH}"
GLEAKS_TAR="${GLEAKS_FOLDER}.tar.gz"
echo "Downloading ${GLEAKS_TAR}"
curl -LO "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GLEAKS_TAR}"
mkdir -p /tmp/"${GLEAKS_FOLDER}"
tar -C /tmp/"${GLEAKS_FOLDER}" -xzvf "${GLEAKS_TAR}"
cp /tmp/"${GLEAKS_FOLDER}"/gitleaks "${USR_BIN_PATH}"gitleaks
chmod +x "${USR_BIN_PATH}"gitleaks

## Download and install kube-score (https://github.com/zegl/kube-score)
K8SCORE_TAR="kube-score_${KUBE_SCORE_VERSION}_linux_${ARCH}"
echo "Downloading ${K8SCORE_TAR}"
curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/${K8SCORE_TAR}" -o "${USR_BIN_PATH}kube-score"
chmod +x "${USR_BIN_PATH}"kube-score

## Download and install tfsec (https://github.com/aquasecurity/tfsec)
TFSEC_TAR="tfsec-linux-${ARCH}"
echo "Downloading ${TFSEC_TAR}"
curl -L "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/${TFSEC_TAR}" -o "${USR_BIN_PATH}tfsec"
chmod +x "${USR_BIN_PATH}"tfsec

## Download and install kubesec (https://github.com/controlplaneio/kubesec)
K8SSEC_TAR="kubesec_linux_${ARCH_ALT_NAME}.tar.gz"
if [ ! -f "${K8SSEC_TAR}" ]; then
    echo "Downloading ${K8SSEC_TAR}"
    curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/${K8SSEC_TAR}"
fi
echo "Installing ${K8SSEC_TAR}"
tar -C "${USR_BIN_PATH}" -xzvf "${K8SSEC_TAR}"
mayberm "${K8SSEC_TAR}"

## Download and install nodeJS (https://nodejs.org)
NODE_TAR=node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz
# if file not there, download it
if [ ! -f "${NODE_TAR}" ]; then
    echo "Downloading ${NODE_TAR}"
    curl -LO "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}"
fi
if [ ! -d "${USR_BIN_PATH}"nodejs/node-v${NODE_VERSION}-linux-"${NODE_ARCH}" ]; then
    echo "Installing ${NODE_TAR}"
    tar -C "${USR_BIN_PATH}" -xzf "${NODE_TAR}"
    mv -f "${USR_BIN_PATH}"node-v${NODE_VERSION}-linux-"${NODE_ARCH}" "${USR_BIN_PATH}"nodejs
    chmod +x "${USR_BIN_PATH}"nodejs/bin/node
    chmod +x "${USR_BIN_PATH}"nodejs/bin/npm
    mayberm "${NODE_TAR}"
else
    echo "NodeJS already installed"
fi



