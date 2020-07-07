#!/usr/bin/env bash

rm -rf AppDir appimage-builder-cache
rm *.AppImage*
mkdir -p appimage-builder-cache
cp ~/Downloads/runtime-x86_64 appimage-builder-cache/
UPDATE_INFO="gh-releases-zsync|ShiftLeftSecurity|sast-scan|latest|*x86_64.AppImage.zsync" appimage-builder --recipe appimage-builder.yml --skip-test
rm -rf AppDir appimage-builder-cache
chmod +x *.AppImage
