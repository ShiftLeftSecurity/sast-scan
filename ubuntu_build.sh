#!/bin/bash
set -e

# This script fulfills all requirements in an Ubuntu 22.04 environment to build the AppImage for sast-scan
# It might work in other debian based environments but it has not been tested.
# Furthermore, the AppImage Process does add ubuntu repositories for 22.04 so it is not guaranteed to work outside
# of that environment (or derivatives).
# AppImage generation is rather slow by nature and this script installs a set of packages, we recommend running it
# within the confines of an LXC container or similar.

# Install all dependencies that come from the distro package manager.
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends python3 python3-dev \
        python3-pip python3-setuptools patchelf desktop-file-utils \
        libgdk-pixbuf2.0-dev php php-curl php-zip php-bcmath php-json \
        php-pear php-mbstring php-dev php-xml wget curl git unzip \
        adwaita-icon-theme libfuse2 squashfs-tools zsync

# Build the cache folder if missing
mkdir -p appimage-builder-cache

# Download latest AppImage Builder Tool
wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-"${ARCH}".AppImage
chmod +x appimagetool-"${ARCH}".AppImage
./appimagetool-"${ARCH}".AppImage --appimage-extract
ln -s /squashfs-root/AppRun ./appimage-builder-cache/appimagetool

# Download latest AppImage Builder Runtime
wget https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-"${ARCH}" -O ./appimage-builder-cache/runtime-"${ARCH}"
chmod +x ./appimage-builder-cache/runtime-"${ARCH}"

# Install appimage-builder python package, this version is forked to account for arm64 architecture name missmatches
# which cause issues when building an AppImage for ubuntu
# (see https://github.com/AppImageCrafters/appimage-builder/pull/318)
python3 -m pip install git+https://github.com/perrito666/appimage-builder.git

# This variable is expected by AppImage builder
export UPDATE_INFO="gh-releases-zsync|ShiftLeftSecurity|sast-scan|latest|*${ARCH}.AppImage.zsync"

# Add the newly installed tools to the path
export PATH="${PWD}/AppDir/usr/bin:${PWD}/AppDir/usr/bin/nodejs/bin:${PWD}/appimage-builder-cache:${PATH}"

# This is the script to build X86_68/amd64 AppImages, AppImage can't cross build ootb so we do not.

# Uncomment this for debugging purposes, this will reuse the same folder, it is quite unstable as AppImage
# modifies the files to depend on relative envs so after that process ran these will no longer work outside of it.
#export KEEP_BUILD_ARTIFACTS=true

# Build App Image for this arch
appimage-builder --recipe "${BUILDER_SCRIPT}" --skip-test

