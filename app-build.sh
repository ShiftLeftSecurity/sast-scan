#!/usr/bin/env bash

rm -rf AppDir appimage-builder-cache
rm *.AppImage*
UPDATE_INFO="gh-releases-zsync|ShiftLeftSecurity|sast-scan|latest|*x86_64.AppImage.zsync" appimage-builder --recipe appimage-builder.yml --skip-test
rm -rf AppDir appimage-builder-cache
